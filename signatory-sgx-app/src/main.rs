#[cfg(target_env = "sgx")]
mod sgx_app;

#[cfg(target_env = "sgx")]
fn main() -> std::io::Result<()> {
    // "signatory" stream is provided by the enclave runner
    // user call extension (in signatory-sgx signer)
    let signatory_signer = std::net::TcpStream::connect("signatory")?;
    println!("signatory-sgx-app connected");
    sgx_app::entry(signatory_signer)
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    println!("`signatory-sgx-app` should be compiled for `x86_64-fortanix-unknown-sgx` target");
}
