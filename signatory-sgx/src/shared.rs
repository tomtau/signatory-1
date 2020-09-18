use serde::{Deserialize, Serialize};
use sgx_isa::{Keypolicy, Keyrequest};
use std::convert::TryInto;
use thiserror::Error;

/// keyseal is fixed in the enclave app
pub type AesGcm128SivNonce = [u8; 12];

/// it can potentially be fixed size, as one always seals the ed25519 keypairs
pub type Ciphertext = Vec<u8>;

/// this partially duplicates `Keyrequest` from sgx-isa,
/// which doesn't implement serde traits
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct KeyRequest {
    pub keyname: u16,
    pub keypolicy: u16,
    pub isvsvn: u16,
    pub cpusvn: [u8; 16],
    pub attributemask: [u64; 2],
    pub keyid: PublicKey,
    pub miscmask: u32,
}

impl TryInto<Keyrequest> for KeyRequest {
    type Error = ();

    fn try_into(self) -> Result<Keyrequest, ()> {
        let keypolicy = Keypolicy::from_bits(self.keypolicy).ok_or(())?;
        Ok(Keyrequest {
            keyname: self.keyname,
            keypolicy,
            isvsvn: self.isvsvn,
            cpusvn: self.cpusvn,
            attributemask: self.attributemask,
            keyid: self.keyid,
            miscmask: self.miscmask,
            ..Default::default()
        })
    }
}

impl From<Keyrequest> for KeyRequest {
    fn from(kr: Keyrequest) -> Self {
        KeyRequest {
            keyname: kr.keyname,
            keypolicy: kr.keypolicy.bits(),
            isvsvn: kr.isvsvn,
            cpusvn: kr.cpusvn,
            attributemask: kr.attributemask,
            keyid: kr.keyid,
            miscmask: kr.miscmask,
        }
    }
}

/// Returned from the enclave app after keygen
/// and expected to be persisted by tmkms
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SealedKeyData {
    pub seal_key_request: KeyRequest,
    pub nonce: AesGcm128SivNonce,
    pub sealed_secret: Ciphertext,
}

/// ed25519 pubkey alias
pub type PublicKey = [u8; 32];

/// message to be signed
pub type Message = Vec<u8>;

/// request sent to the enclave app
#[derive(Debug, Serialize, Deserialize)]
pub enum SgxRequest {
    /// generate a new keypair
    KeyGen,
    /// return the public key of the keypair
    GetPublicKey,
    /// import the previously persisted sealed keypair
    Import(SealedKeyData),
    /// sign a message
    Sign(Message),
    /// gracefully shutdown the enclave app
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SgxResponse {
    /// freshly generated sealed keypair
    KeyPair(SealedKeyData),
    /// ed25519 public key
    PublicKey(PublicKey),
    /// ed25519 signature on the message
    Signed(ed25519::Signature),
    /// something went wrong
    Error(SgxResponseError),
}

/// Simplified error responses
#[derive(Debug, Serialize, Deserialize, Error)]
pub enum SgxResponseError {
    /// if one calls keygen or import twice
    #[error("the signing key is already set in the enclave app")]
    KeyAlreadySet,
    /// if tries to sign/get public key before import or keygen
    #[error("the signing key is not set in the enclave app")]
    KeyNotSet,
    /// if keygen failed to seal the keypair
    #[error("sealing of the signing key failed")]
    SealFailed,
    /// if import failed to unseal the keypair
    #[error("unsealing of the signing key failed")]
    UnsealFailed,
    /// bincode or socket problem
    #[error("unexpected error (wrong or malformed response etc.)")]
    Unexpected,
}
