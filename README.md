# [G]ate [A]ccess - X Firmware
this repository contains the firmware for the GA-X Project ([click here, to learn more](https://github.com/codecrafter404/gax-app))

# How to build
- Setup your development environment as documented in the [Rust on ESP Book](https://docs.esp-rs.org/book/installation/riscv-and-xtensa.html)
- clone the git repo: `git clone https://github.com/codecrafter404/gax` (and navigate in the directory)
- change the constants (at the start of the file) in [`build.rs`](https://github.com/codecrafter404/gax/build.rs) to your liking (**at least the mac-address has the be changed **)
- change the pins (at the start of the file) in [`main.rs`](https://github.com/codecrafter404/gax/blob/5bc91ee247f9be0c35db2bc0fadcc3324ca83bd2/src/main.rs#L92) to your liking (**at least the mac-address has the be changed **)
    - `trigger_pin` this is the pin that will be set high when the gate is being opened
    - `error_ping` this is the pin connectected to the status LED
- prepare your breadboard or something similar (to comply with the esp32's power restrictions) by using the pins as configured in the last step
- connect your esp32 to your computer
- run `cargo run --release` to compile and flash the firmware
- the QR-Code is in `config_dir/qr.png`. THIS QR-CODE CONTAINS THE SECRETS TO TRIGGER THE OPEN; HANDLE IT WITH THE CORRESPONDING CAUTION

# Vision (TODO's)
- [X] Open and close the gate
- [X] Anti replay attack mechanism -> a challange response structure (ECDSA based)
- [X] Generate QR-Code (or at least the information stored) automatically on buildtime
    - [X] all options are constants, which can be changed -> those have to be stored in the QR-Code
    - [X] create JSON struct
- [X] Metadata-Backend ([see here](https://github.com/codecrafter404/gax-app))
- [X] An status LED indicating the operation status through blinking
    - [X] make it async!
- [X] Documentation📘
