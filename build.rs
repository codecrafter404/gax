use std::path::Path;

use k256::ecdsa::{SigningKey, VerifyingKey};

// use rand::thread_rng;

fn main() -> color_eyre::Result<()> {
    // fn main() {
    embuild::espidf::sysenv::output();

    let key_pair_dir = Path::new("./key_dir/");
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
    Ok(())
}
