use std::time::Duration;

use esp32_nimble::{utilities::BleUuid, uuid128};
use serde::{de::Error, Deserialize};

#[derive(Debug, Deserialize())]
struct DeviceConfig {
    ble_name: String,
    service_uuid: String,
    lock_char_uuid: String,
    open_time_in_ms: u32,
}

// pub const BLE_NAME: &str = "GAX 0.1";
// pub const SERVICE_UID: BleUuid = uuid128!("5f9b34fb-0000-1000-8000-00805f9b34fb");
// pub const LOCK_CHAR_UID: BleUuid = uuid128!("00000000-DEAD-BEEF-0001-000000000000");
// pub const OPEN_TIME: Duration = Duration::from_secs(2);
pub fn parse_config(config: &str) -> Result<DeviceConfig, Error> {
    Ok(serde_json::from_str(config))
}
