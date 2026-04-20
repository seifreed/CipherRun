#![no_main]

use cipherrun::application::{CompareScanIds, HostPortDaysInput, HostPortInput};
use cipherrun::utils::network::split_target_host_port;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = CompareScanIds::parse(input);
    let _ = HostPortInput::parse_with_default_port(input, 443);
    let _ = HostPortDaysInput::parse(input);
    let _ = split_target_host_port(input);
});
