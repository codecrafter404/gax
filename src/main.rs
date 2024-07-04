use esp32_nimble::utilities::BleUuid;
use esp32_nimble::{BLEAddress, BLEAdvertisementData, BLEDevice, BLEError, NimbleProperties};
use esp_idf_svc::hal::gpio::{Output, Pin};
use esp_idf_svc::hal::{gpio::PinDriver, peripherals::Peripherals};
use esp_idf_svc::sys::{
    EspError, CONFIG_BT_NIMBLE_TASK_STACK_SIZE, CONFIG_NIMBLE_TASK_STACK_SIZE, NIMBLE_HS_STACK_SIZE,
};
use k256::ecdsa::VerifyingKey;
use k256::ecdsa::{signature::Verifier, Signature};
use log::LevelFilter;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    sync::Mutex,
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone)]
struct BLEChallenge {
    time: SystemTime,
    challenge_bytes: [u8; 64],
    address: BLEAddress,
}
#[derive(Debug, Deserialize)]
struct DeviceConfig {
    pub ble_name: String,
    pub service_uuid: String,
    pub lock_char_uuid: String,
    pub meta_char_uuid: String,
    pub open_time_in_ms: u64,
}

#[derive(Debug, Serialize, Clone)]
struct MetaDataStruct {
    pub power_on_hours: f64,
    pub trigger_pin: i32,
    pub status_led_pin: i32,
}

fn main() {
    let power_on = std::time::SystemTime::now();

    let dp: Peripherals = Peripherals::take().unwrap();

    // config
    let config: DeviceConfig =
        serde_json::from_str(include_str!("../config_dir/device_config.json")).unwrap();
    let ble_name: &str = &config.ble_name;
    let service_uid: BleUuid = BleUuid::from_uuid128_string(&config.service_uuid).unwrap();
    let lock_char_uid: BleUuid = BleUuid::from_uuid128_string(&config.lock_char_uuid).unwrap();
    let open_time: Duration = Duration::from_millis(config.open_time_in_ms);
    let meta_char_uid: BleUuid = BleUuid::from_uuid128_string(&config.meta_char_uuid).unwrap();

    // change those PINS in order to modify the pinout
    let trigger_pin: esp_idf_svc::hal::gpio::Gpio16 = dp.pins.gpio16;
    let error_pin: esp_idf_svc::hal::gpio::Gpio17 = dp.pins.gpio17;

    let meta_data = MetaDataStruct {
        power_on_hours: 0.,
        trigger_pin: trigger_pin.pin(),
        status_led_pin: error_pin.pin(),
    };
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

    // init config

    // Change the folowing gpio pins to your desire!
    let mut led_pin = PinDriver::output(trigger_pin).unwrap();
    let error_pin = Arc::new(Mutex::new(PinDriver::output(error_pin).unwrap()));

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

    let service = server.create_service(service_uid);

    // metadata characteristic
    let meta_char = service
        .lock()
        .create_characteristic(meta_char_uid, NimbleProperties::READ);

    meta_char.lock().on_read(move |attr, _ble_con_desc| {
        let mut meta = (&meta_data).clone();
        meta.power_on_hours = match power_on.elapsed() {
            Ok(e) => e.as_secs_f64() / (60. * 60.),
            Err(why) => {
                log::error!("[❌] Failed to read power on hours: {}", why.to_string());
                -1.
            }
        };
        let res = match serde_json::to_string(&meta) {
            Ok(x) => x,
            Err(why) => {
                log::error!("[❌] Failed to prepare json: {}", why.to_string());
                "".to_owned()
            }
        };
        attr.set_value(res.as_bytes());
        log::info!(
            "[ℹ️] ({}) requested the metadata",
            _ble_con_desc.address().to_string()
        )
    });

    let lock_char = service.lock().create_characteristic(
        lock_char_uid,
        NimbleProperties::READ | NimbleProperties::WRITE,
    );
    let verifying_key = VerifyingKey::from_sec1_bytes(include_bytes!("../config_dir/public.bin"))
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
    setup_ble(&mut ble_device, ble_name, service_uid).unwrap();
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
        match open_door(&res, &mut led_pin, open_time) {
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
    open_time: Duration,
) -> Result<(), EspError> {
    log::info!("[✔️] ({}) opening gate", addr);

    door.set_high()?;
    std::thread::sleep(open_time);
    door.set_low()?;

    Ok(())
}
fn setup_ble(device: &mut BLEDevice, ble_name: &str, service_uid: BleUuid) -> Result<(), BLEError> {
    BLEDevice::set_device_name(ble_name)?;
    device.get_advertising().lock().set_data(
        BLEAdvertisementData::new()
            .name(ble_name)
            .appearance(0x180)
            .add_service_uuid(service_uid),
    )?;
    device.get_advertising().lock().start()?;
    Ok(())
}
