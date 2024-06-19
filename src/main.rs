use std::{thread::sleep, time::Duration};

use esp32_nimble::{
    utilities::BleUuid, uuid128, BLEAdvertisementData, BLEDevice, BLEError, NimbleProperties,
};
use esp_idf_svc::hal::{gpio::PinDriver, peripherals::Peripherals};
use rand::Rng;

const BLE_NAME: &str = "GAX 0.1";
const SERVICE_UID: BleUuid = BleUuid::Uuid32(0x1337);
const LOCK_CHAR_UID: BleUuid = uuid128!("00000000-DEAD-BEEF-0001-000000000000");
const TIME_CHAR_UID: BleUuid = uuid128!("00000000-DEAD-BEEF-0002-000000000000");

// TODO: https://pub.dev/documentation/ecdsa/latest/ecdsa/ecdsa-library.html
// TODO: https://docs.rs/ecdsa/latest/ecdsa/struct.SigningKey.html

fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("👋Hello, world!");
    let dp = Peripherals::take().unwrap();
    let mut led = PinDriver::output(dp.pins.gpio2).unwrap();
    let mut ble_device = BLEDevice::take();
    let server = ble_device.get_server();
    server.on_connect(|_server, desc| {
        log::info!("[🔌] Device '{}' connected", desc.address());
    });
    server.on_disconnect(|desc, reason| {
        log::info!(
            "[🔌] Device '{}' disconnected ({:?})",
            desc.address(),
            reason
        )
    });

    led.set_high().unwrap();
    let service = server.create_service(SERVICE_UID);
    let lock_char = service.lock().create_characteristic(
        LOCK_CHAR_UID,
        NimbleProperties::READ | NimbleProperties::WRITE,
    );
    lock_char
        .lock()
        .on_read(move |attr, _ble_con_desc| {
            let num = rand::thread_rng().gen::<u64>();
            log::info!("[🎲] Sending random number: {}", num);
            attr.set_value(&num.to_le_bytes());
        })
        .on_write(|a| log::info!("{:?}", String::from_utf8(a.recv_data().to_vec())));
    setup_ble(&mut ble_device).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn setup_ble(device: &mut BLEDevice) -> Result<(), BLEError> {
    BLEDevice::set_device_name(BLE_NAME)?;
    device.get_advertising().lock().set_data(
        BLEAdvertisementData::new()
            .name(BLE_NAME)
            .appearance(0x180)
            .add_service_uuid(SERVICE_UID),
    )?;
    device.get_advertising().lock().start()?;
    Ok(())
}
