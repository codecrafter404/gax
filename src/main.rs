use esp32_nimble::{BLEAddress, BLEAdvertisementData, BLEDevice, BLEError, NimbleProperties};
use esp_idf_svc::hal::gpio::Output;
use esp_idf_svc::hal::{gpio::PinDriver, peripherals::Peripherals};
use esp_idf_svc::sys::{
    EspError, CONFIG_BT_NIMBLE_TASK_STACK_SIZE, CONFIG_NIMBLE_TASK_STACK_SIZE, NIMBLE_HS_STACK_SIZE,
};
use k256::ecdsa::VerifyingKey;
use k256::ecdsa::{signature::Verifier, Signature};
use log::LevelFilter;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::{
    sync::Mutex,
    time::{Duration, SystemTime},
};

mod constants;

#[derive(Debug, Clone)]
struct BLEChallenge {
    time: SystemTime,
    challenge_bytes: [u8; 64],
    address: BLEAddress,
}

fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();
    esp_idf_svc::log::set_target_level("*", LevelFilter::Trace).unwrap();

    log::info!(
        "[🐛] Stack Size: {}, {}, {}",
        NIMBLE_HS_STACK_SIZE,
        CONFIG_BT_NIMBLE_TASK_STACK_SIZE,
        CONFIG_NIMBLE_TASK_STACK_SIZE
    );

    let dp = Peripherals::take().unwrap();

    // Change the folowing gpio pins to your desire!
    let mut led_pin = PinDriver::output(dp.pins.gpio16).unwrap();
    let error_pin = Arc::new(Mutex::new(PinDriver::output(dp.pins.gpio17).unwrap()));

    let mut ble_device = BLEDevice::take();
    let challenge: Arc<Mutex<Vec<BLEChallenge>>> = Arc::new(Mutex::new(Vec::new()));
    let server = ble_device.get_server();
    let challenge_disconnect = challenge.clone();
    server.on_connect(|_server, desc| {
        log::info!("[🔌] Device '{}' connected", desc.address());
    });
    server.on_disconnect(move |desc, reason| {
        log::info!(
            "[🔌] Device '{}' disconnected ({:?})",
            desc.address(),
            reason
        );
        {
            let mut challenges = match challenge_disconnect.lock() {
                Ok(x) => x,
                Err(why) => {
                    log::error!(
                        "[❌] Mutex Lock Error while trying to clean challenges: {:?}",
                        why
                    );

                    return;
                }
            };
            *challenges = challenges
                .clone()
                .into_iter()
                .filter(|x| x.address != desc.address())
                .collect();
            log::info!("[♻️] Cleaned up challenges: {} remaining", challenges.len());
        }
    });

    let service = server.create_service(constants::SERVICE_UID);
    let lock_char = service.lock().create_characteristic(
        constants::LOCK_CHAR_UID,
        NimbleProperties::READ | NimbleProperties::WRITE,
    );
    let verifying_key = VerifyingKey::from_sec1_bytes(include_bytes!("../key_dir/public.bin"))
        .expect("[❌] Failed to parse Sec1-Bytes public key");
    let verifying_key = Arc::new(verifying_key);
    let read_challenge = challenge.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    lock_char
        .lock()
        .on_read(move |attr, _ble_con_desc| {
            let mut challenge_bytes: [u8; 64] = [Default::default(); 64];
            thread_rng().fill(&mut challenge_bytes);
            log::info!(
                "[🎲] ({}) Sending challenge bytes '{}'",
                _ble_con_desc.address(),
                bytes_to_hex_string(&challenge_bytes)
            );
            {
                // log::info!("Lock MUTEX");
                let mut challengens = match read_challenge.lock() {
                    Ok(x) => x,
                    Err(why) => {
                        log::error!(
                            "[❌] ({}) Mutex lock error: {:?}",
                            _ble_con_desc.address(),
                            why
                        );
                        return;
                    }
                };
                challengens.push(BLEChallenge {
                    time: SystemTime::now(),
                    challenge_bytes: challenge_bytes.clone(),
                    address: _ble_con_desc.address().clone(),
                })
            }
            attr.set_value(&challenge_bytes);
        })
        .on_write(move |args| {
            let data = args.recv_data();
            log::info!(
                "[👀] ({}) Got challenge response '{}'",
                args.desc().address(),
                bytes_to_hex_string(&data)
            );
            if data.len() < 64 {
                log::error!(
                    "[❌] ({}) Got only {} bytes, expected 65",
                    args.desc().address(),
                    data.len()
                );
                args.reject_with_error_code(0x01);
                return;
            }
            let challenge_data = &data[..64];

            // check if challenge exists & is in time
            {
                let mut challenges = match challenge.lock() {
                    Ok(x) => x,
                    Err(why) => {
                        log::error!(
                            "[❌] ({}) Mutex lock error: {:?}",
                            args.desc().address(),
                            why
                        );
                        args.reject_with_error_code(0x05);
                        return;
                    }
                };
                let challenge_result = match challenges.iter().find(|x| {
                    x.address == args.desc().address() && x.challenge_bytes == challenge_data
                }) {
                    Some(x) => x,
                    None => {
                        log::error!(
                            "[⛔] ({}) Opening-Request denied: couldn't find challenge: '{}'",
                            args.desc().address(),
                            bytes_to_hex_string(challenge_data)
                        );
                        args.reject_with_error_code(0x06);
                        return;
                    }
                };
                if challenge_result.time.elapsed().expect("Time ran backwards")
                    > Duration::from_secs(90)
                {
                    log::error!(
                        "[⛔] ({}) Opening-Request denied: challenge expired",
                        args.desc().address()
                    );
                    clean_up_challenges(&mut challenges, challenge_data, &args.desc().address());
                    args.reject_with_error_code(0x07);
                    return;
                }
                clean_up_challenges(&mut challenges, challenge_data, &args.desc().address());
            }

            assert_eq!(challenge_data.len(), 64);
            let signature = &data[64..]; // created from a SHA256 digest of the challenge
            let signature = match Signature::from_der(signature) {
                Ok(x) => x,
                Err(why) => {
                    log::error!(
                        "[❌] ({}) Invalid DER signature: {:?}",
                        args.desc().address(),
                        why
                    );
                    args.reject_with_error_code(0x02);
                    return;
                }
            };
            match verifying_key.verify(&challenge_data, &signature) {
                Ok(_) => match tx.send(args.desc().address()) {
                    // Ok(_) => match open_door(&args.desc().address()) {
                    Ok(_) => {}
                    Err(why) => {
                        log::error!("[❌] Failed to tx: {:?}", why);
                        args.reject_with_error_code(0x08);
                        return;
                    }
                },
                Err(why) => {
                    log::error!(
                        "[❌] ({}) Signature verification failed: {:?}",
                        args.desc().address(),
                        why
                    );
                    args.reject_with_error_code(0x04);
                    return;
                }
            }
        });
    setup_ble(&mut ble_device).unwrap();
    led_pin.set_low().unwrap();
    log::info!("[🚋] Starting BLE Server");
    loop {
        // std::thread::sleep(Duration::from_secs(2))
        let res = match rx.recv() {
            Ok(x) => x,
            Err(why) => {
                log::error!("[❌] Failed to rx: {:?}", why);
                continue;
            }
        };
        match open_door(&res, &mut led_pin) {
            Ok(_) => {
                let error = error_pin.clone();
                std::thread::spawn(|| {
                    blink_in_sequence(error, &[true, true, true, true, true])
                        .expect("Failed to show success sequence -> critical hardware issue");
                });
            }
            Err(why) => {
                log::error!("[❌] ({}) Failed to open door: {:?}", &res, why);
                let error = error_pin.clone();
                std::thread::spawn(|| {
                    blink_in_sequence(error, &[true, false, true, true, true])
                        .expect("Failed to show error sequence -> criticial hardware issue");
                });
            }
        }
    }
}
fn blink_in_sequence<T: esp_idf_svc::hal::gpio::Pin>(
    led: Arc<Mutex<PinDriver<T, Output>>>,
    sequence: &[bool],
) -> Result<(), EspError> {
    let mut led = led.lock().expect("Unable to lock MUTEX");
    for x in sequence {
        if *x {
            led.set_high()?;
            std::thread::sleep(Duration::from_millis(500));
            led.set_low()?;
        } else {
            std::thread::sleep(Duration::from_millis(500));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}
fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut str = String::new();
    bytes.into_iter().for_each(|x| {
        str.push_str(&format!("{:0>2x}", x));
    });
    str
}

fn clean_up_challenges(
    challenges: &mut Vec<BLEChallenge>,
    challenge_data: &[u8],
    addr: &BLEAddress,
) {
    *challenges = challenges
        .clone()
        .into_iter()
        .filter(|x| !(x.address == *addr && x.challenge_bytes == challenge_data))
        .collect();
}
fn open_door<T: esp_idf_svc::hal::gpio::Pin>(
    addr: &BLEAddress,
    door: &mut PinDriver<T, Output>,
) -> Result<(), EspError> {
    log::info!("[✔️] ({}) opening gate", addr);

    door.set_high()?;
    std::thread::sleep(constants::OPEN_TIME);
    door.set_low()?;

    Ok(())
}
fn setup_ble(device: &mut BLEDevice) -> Result<(), BLEError> {
    BLEDevice::set_device_name(constants::BLE_NAME)?;
    device.get_advertising().lock().set_data(
        BLEAdvertisementData::new()
            .name(constants::BLE_NAME)
            .appearance(0x180)
            .add_service_uuid(constants::SERVICE_UID),
    )?;
    device.get_advertising().lock().start()?;
    Ok(())
}
