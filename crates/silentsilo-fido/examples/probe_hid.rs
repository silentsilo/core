//! Lists the security keys this computer sees and whether each one opens:
//! the first thing to run when a key is plugged in and the app says none is.

fn main() {
    println!("status: {:?}", silentsilo_fido::status());
    list();
}

#[cfg(not(windows))]
fn list() {
    let api = match hidapi::HidApi::new() {
        Ok(api) => api,
        Err(e) => {
            println!("USB HID could not be read: {e}");
            return;
        }
    };
    println!("=== FIDO interfaces (usage page 0xF1D0) ===");
    for d in api
        .device_list()
        .filter(|d| d.usage_page() == 0xF1D0 && d.usage() == 0x01)
    {
        let opens = match d.open_device(&api) {
            Ok(_) => "opens".to_string(),
            Err(e) => format!("does not open: {e}"),
        };
        println!(
            "  {:04x}:{:04x} {} at {:?}: {opens}",
            d.vendor_id(),
            d.product_id(),
            d.product_string().unwrap_or("?"),
            d.path()
        );
    }
}

/// Windows reaches keys through its own WebAuthn API, not raw HID.
#[cfg(windows)]
fn list() {}
