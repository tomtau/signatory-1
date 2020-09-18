/// helpers for keypair sealing/unsealing
mod keypair_seal;

use ed25519_dalek::{Keypair, Signature, Signer};
use rand::rngs::OsRng;
use signatory_sgx::shared::{SgxRequest, SgxResponse, SgxResponseError};
use std::net::TcpStream;

/// a simple req-rep handling loop
/// `TcpStream` is either provided in tests or from the "signatory-sgx"
/// enclave runner's user call extension.
pub fn entry(mut signatory_signer: TcpStream) -> std::io::Result<()> {
    let mut csprng = OsRng {};
    let mut keypair: Option<Keypair> = None;
    loop {
        let request: bincode::Result<SgxRequest> = bincode::deserialize_from(&mut signatory_signer);
        match request {
            Ok(SgxRequest::KeyGen) => {
                let response = if keypair.is_some() {
                    SgxResponse::Error(SgxResponseError::KeyAlreadySet)
                } else {
                    let kp = Keypair::generate(&mut csprng);
                    if let Ok(sealed_data) = keypair_seal::seal(&mut csprng, &kp) {
                        keypair = Some(kp);
                        SgxResponse::KeyPair(sealed_data)
                    } else {
                        SgxResponse::Error(SgxResponseError::SealFailed)
                    }
                };

                if let Err(e) = bincode::serialize_into(&mut signatory_signer, &response) {
                    eprintln!("signatory-sgx-app keygen error: {}", e);
                    break;
                }
            }
            Ok(SgxRequest::GetPublicKey) => {
                let response = match keypair {
                    Some(ref kp) => SgxResponse::PublicKey(kp.public.to_bytes()),
                    _ => SgxResponse::Error(SgxResponseError::KeyNotSet),
                };
                if let Err(e) = bincode::serialize_into(&mut signatory_signer, &response) {
                    eprintln!("signatory-sgx-app get pubkey error: {}", e);
                    break;
                }
            }
            Ok(SgxRequest::Import(sealed_data)) => {
                let response = if keypair.is_some() {
                    SgxResponse::Error(SgxResponseError::KeyAlreadySet)
                } else if let Ok(kp) = keypair_seal::unseal(&sealed_data) {
                    let public_key = kp.public.to_bytes();
                    keypair = Some(kp);
                    SgxResponse::PublicKey(public_key)
                } else {
                    SgxResponse::Error(SgxResponseError::UnsealFailed)
                };

                if let Err(e) = bincode::serialize_into(&mut signatory_signer, &response) {
                    eprintln!("signatory-sgx-app import error: {}", e);
                    break;
                }
            }
            Ok(SgxRequest::Sign(msg)) => {
                let response = match keypair {
                    Some(ref kp) => {
                        let signature: Signature = kp.sign(&msg);
                        SgxResponse::Signed(signature)
                    }
                    _ => SgxResponse::Error(SgxResponseError::KeyNotSet),
                };

                if let Err(e) = bincode::serialize_into(&mut signatory_signer, &response) {
                    eprintln!("signatory-sgx-app sign error: {}", e);
                    break;
                }
            }
            Ok(SgxRequest::Shutdown) => {
                break;
            }
            Err(_e) => {
                // generally empty buffer
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{PublicKey, Verifier};
    use std::net::{TcpListener, TcpStream};

    // can be run with `cargo test --target x86_64-fortanix-unknown-sgx`
    #[test]
    fn test_basic_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handler = std::thread::spawn(move || entry(TcpStream::connect(addr).unwrap()));
        let (mut stream_signer, _) = listener.accept().unwrap();
        let _ = bincode::serialize_into(&mut stream_signer, &SgxRequest::KeyGen);
        let response1: SgxResponse = bincode::deserialize_from(&mut stream_signer).unwrap();
        let pk = match response1 {
            SgxResponse::KeyPair(sealed_data) => sealed_data.seal_key_request.keyid,
            _ => panic!("wrong keygen response"),
        };
        let _ = bincode::serialize_into(&mut stream_signer, &SgxRequest::GetPublicKey);
        let response2: SgxResponse = bincode::deserialize_from(&mut stream_signer).unwrap();
        let pk2 = match response2 {
            SgxResponse::PublicKey(public_key) => public_key,
            _ => panic!("wrong public key response"),
        };
        assert_eq!(pk, pk2, "public keys match");
        let msg = b"hello".to_vec();
        let _ = bincode::serialize_into(&mut stream_signer, &SgxRequest::Sign(msg.clone()));
        let response3: SgxResponse = bincode::deserialize_from(&mut stream_signer).unwrap();
        let sig = match response3 {
            SgxResponse::Signed(sig) => sig,
            _ => panic!("wrong sign response"),
        };
        let public_key = PublicKey::from_bytes(&pk).expect("valid public key");
        assert!(public_key.verify(&msg, &sig).is_ok(), "signature is valid");
        let _ = bincode::serialize_into(&mut stream_signer, &SgxRequest::Shutdown);
        let _ = handler.join();
    }

    #[test]
    fn test_unseal() {
        let mut csprng = OsRng {};
        let kp = Keypair::generate(&mut csprng);
        let sealed_data = keypair_seal::seal(&mut csprng, &kp).unwrap();
        let mut mangled_sealed_data = sealed_data.clone();
        mangled_sealed_data.nonce[0] |= 1;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handler = std::thread::spawn(move || entry(TcpStream::connect(addr).unwrap()));
        let (mut stream_signer, _) = listener.accept().unwrap();
        let _ =
            bincode::serialize_into(&mut stream_signer, &SgxRequest::Import(mangled_sealed_data));
        let response1: SgxResponse = bincode::deserialize_from(&mut stream_signer).unwrap();
        match response1 {
            SgxResponse::Error(SgxResponseError::UnsealFailed) => {
                // ok
            }
            _ => panic!("wrong import response"),
        };
        let _ = bincode::serialize_into(&mut stream_signer, &SgxRequest::Import(sealed_data));
        let response2: SgxResponse = bincode::deserialize_from(&mut stream_signer).unwrap();
        match response2 {
            SgxResponse::PublicKey(pk) => {
                assert_eq!(pk, kp.public.to_bytes(), "public key matches");
            }
            _ => panic!("wrong import response"),
        };

        let _ = bincode::serialize_into(&mut stream_signer, &SgxRequest::Shutdown);
        let _ = handler.join();
    }
}
