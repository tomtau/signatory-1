use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use sgxs_loaders::isgx::Device;
use signatory::{
    ed25519::{self, Signature},
    signature::{Error, Signer},
};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::{future::Future, io, pin::Pin};

/// type alias for outputs in UsercallExtension async return type
type UserCallStream = io::Result<Option<Box<dyn AsyncStream>>>;
use crate::shared::{PublicKey, SealedKeyData, SgxRequest, SgxResponse, SgxResponseError};

/// custom runner for tmkms <-> enclave app communication
/// TODO: Windows support (via random TCP or custom in-memory stream)?
#[derive(Debug)]
struct SignatorySgxRunner {
    enclave_stream: UnixStream,
}

impl UsercallExtension for SignatorySgxRunner {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallStream> + 'future>> {
        async fn connect_stream_inner(this: &SignatorySgxRunner, addr: &str) -> UserCallStream {
            match addr {
                "signatory" => {
                    let stream =
                        tokio::net::UnixStream::from_std(this.enclave_stream.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                _ => Ok(None),
            }
        }
        Box::pin(connect_stream_inner(self, addr))
    }
}

/// controller for launching the enclave app and providing the communication with it
pub struct SignatorySgxSigner {
    stream_to_enclave: UnixStream,
    enclave_app_thread: thread::JoinHandle<()>,
}

impl SignatorySgxSigner {
    /// launches the `signatory-sgx-app` from the provided path
    pub fn launch_enclave_app<P: AsRef<Path>>(sgxs_path: P) -> io::Result<Self> {
        let (stream_to_enclave, enclave_stream) = UnixStream::pair()?;
        let runner = SignatorySgxRunner { enclave_stream };
        let mut device = Device::new()?
            .einittoken_provider(AesmClient::new())
            .build();
        let mut enclave_builder = EnclaveBuilder::new(sgxs_path.as_ref());
        enclave_builder.coresident_signature()?;

        enclave_builder.usercall_extension(runner);
        let enclave = enclave_builder
            .build(&mut device)
            .expect("Failed to build the enclave app");
        let enclave_app_thread = thread::spawn(|| {
            enclave
                .run()
                .expect("Failed to start `signatory-sgx-app` enclave")
        });
        Ok(Self {
            stream_to_enclave,
            enclave_app_thread,
        })
    }

    /// shuts down the `signatory-sgx-app`
    pub fn shutdown_enclave_app(self) {
        let msg = "Failed to shutdown `signatory-sgx-app` enclave";
        bincode::serialize_into(&self.stream_to_enclave, &SgxRequest::Shutdown).expect(msg);
        self.enclave_app_thread.join().expect(msg);
    }

    /// req-rep helper
    fn exchange(&self, request: SgxRequest) -> bincode::Result<SgxResponse> {
        bincode::serialize_into(&self.stream_to_enclave, &request)?;
        bincode::deserialize_from(&self.stream_to_enclave)
    }

    /// generate a new keypair
    pub fn keygen(&self) -> Result<SealedKeyData, SgxResponseError> {
        match self.exchange(SgxRequest::KeyGen) {
            Ok(SgxResponse::KeyPair(sealed_key)) => Ok(sealed_key),
            Ok(SgxResponse::Error(e)) => Err(e),
            _ => Err(SgxResponseError::Unexpected),
        }
    }

    /// get the ed25519 public key
    pub fn public_key(&self) -> Result<PublicKey, SgxResponseError> {
        match self.exchange(SgxRequest::GetPublicKey) {
            Ok(SgxResponse::PublicKey(v)) => Ok(v),
            Ok(SgxResponse::Error(e)) => Err(e),
            _ => Err(SgxResponseError::Unexpected),
        }
    }

    /// sign the provided message payload
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, SgxResponseError> {
        match self.exchange(SgxRequest::Sign(msg.to_vec())) {
            Ok(SgxResponse::Signed(v)) => Ok(v),
            Ok(SgxResponse::Error(e)) => Err(e),
            _ => Err(SgxResponseError::Unexpected),
        }
    }

    /// import the previously persisted keypair
    pub fn import(&self, sealed_key: SealedKeyData) -> Result<PublicKey, SgxResponseError> {
        match self.exchange(SgxRequest::Import(sealed_key)) {
            Ok(SgxResponse::PublicKey(pk)) => Ok(pk),
            Ok(SgxResponse::Error(e)) => Err(e),
            _ => Err(SgxResponseError::Unexpected),
        }
    }
}

impl From<&SignatorySgxSigner> for ed25519::PublicKey {
    /// Returns the public key that corresponds to the one generated in SGX enclave app
    fn from(signer: &SignatorySgxSigner) -> ed25519::PublicKey {
        ed25519::PublicKey(signer.public_key().unwrap())
    }
}

impl Signer<ed25519::Signature> for SignatorySgxSigner {
    /// c: Compute a compact, fixed-sized signature of the given amino/json vote
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, Error> {
        self.sign(msg).map_err(Error::from_source)
    }
}
