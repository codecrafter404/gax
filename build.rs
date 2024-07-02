use std::path::Path;

use k256::ecdsa::SigningKey;
use serde::Serialize;

// use rand::thread_rng;

#[derive(Debug, Serialize)]
struct DeviceConfig {
    ble_name: String,
    service_uuid: String,
    lock_char_uuid: String,
    open_time_in_ms: u32,
    mac: String,
    priv_key: String,
}

pub const BLE_NAME: &str = "GAX 0.1";
pub const SERVICE_UID: &str = "5f9b34fb-0000-1000-8000-00805f9b34fb";
pub const LOCK_CHAR_UID: &str = "00000000-DEAD-BEEF-0001-000000000000";
pub const OPEN_TIME: u32 = 2000;

fn main() -> color_eyre::Result<()> {
    // fn main() {
    embuild::espidf::sysenv::output();

    let key_pair_dir = Path::new("./config_dir/");
    if !key_pair_dir.exists() {
        std::fs::create_dir_all(key_pair_dir)?;
    }
    let priv_key = key_pair_dir.join("private.bin");
    let pub_key = key_pair_dir.join("public.bin");
    if !priv_key.exists() || !pub_key.exists() {
        println!("[⚙️] Generating new private/public keypair");
        if priv_key.exists() {
            std::fs::remove_file(&priv_key)?;
        }
        if pub_key.exists() {
            std::fs::remove_file(&pub_key)?;
        }

        let signing_key = SigningKey::random(&mut rand::thread_rng());
        std::fs::write(priv_key, signing_key.to_bytes())?;
        std::fs::write(pub_key, signing_key.verifying_key().to_sec1_bytes())?;
    }
    let config = DeviceConfig {
        ble_name: BLE_NAME.to_owned(),
        service_uuid: SERVICE_UID.to_owned(),
        lock_char_uuid: LOCK_CHAR_UID.to_owned(),
        open_time_in_ms: OPEN_TIME.to_owned(),
        mac: "".to_owned(),
        priv_key: "".to_owned(),
    };

    let config = serde_json::to_string_pretty(&config)?;

    std::fs::write("./config_dir/device_config.json", config)?;
    Ok(())
}
