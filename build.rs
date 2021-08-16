// SPDX-License-Identifier: Apache-2.0

fn main() {
    if std::path::Path::new("/dev/sgx_enclave").exists() {
        println!("cargo:rustc-cfg=has_sgx");
    }
}
