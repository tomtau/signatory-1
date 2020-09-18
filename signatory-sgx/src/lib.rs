/// module shared between the enclave app and the signer
pub mod shared;
#[cfg(not(target_env = "sgx"))]
mod signer;

#[cfg(not(target_env = "sgx"))]
pub use signer::SignatorySgxSigner;
