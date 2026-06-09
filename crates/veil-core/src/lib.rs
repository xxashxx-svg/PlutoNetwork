//! veil-core — the E2EE engine. Wraps OpenMLS so the rest of the app
//! never touches raw crypto. Everything crossing the network is bytes
//! that the server can't read.

use std::collections::HashMap;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error)]
pub enum VeilError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("bad bytes on the wire: {0}")]
    Wire(String),
    #[error("no chat with that id")]
    UnknownChat,
    #[error("{0}")]
    Mls(String),
}

// so we don't write map_err soup everywhere
macro_rules! mls {
    ($e:expr) => {
        $e.map_err(|err| VeilError::Mls(err.to_string()))
    };
}
macro_rules! wire {
    ($e:expr) => {
        $e.map_err(|err| VeilError::Wire(err.to_string()))
    };
}

/// what recv() hands back — where it belongs, who sent it, and the text (if any)
pub struct Incoming {
    pub chat_id: Vec<u8>,
    pub sender: Vec<u8>,
    pub plaintext: Option<Vec<u8>>,
}

/// One user/device. Owns the keys, the provider, and all open chats.
pub struct Client {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    chats: HashMap<Vec<u8>, MlsGroup>,
}

impl Client {
    pub fn new(name: &str) -> Result<Self, VeilError> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| VeilError::Crypto(e.to_string()))?;
        mls!(signer.store(provider.storage()))?;
        Ok(Self {
            provider,
            credential: CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.public().into(),
            },
            signer,
            chats: HashMap::new(),
        })
    }

    /// fresh key package to publish on the server so people can invite us
    pub fn key_package(&self) -> Result<Vec<u8>, VeilError> {
        let bundle = mls!(KeyPackage::builder().build(
            CIPHERSUITE,
            &self.provider,
            &self.signer,
            self.credential.clone(),
        ))?;
        wire!(bundle.key_package().tls_serialize_detached())
    }

    pub fn create_chat(&mut self) -> Result<Vec<u8>, VeilError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = mls!(MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        ))?;
        let id = group.group_id().as_slice().to_vec();
        self.chats.insert(id.clone(), group);
        Ok(id)
    }

    /// add someone by their published key package.
    /// returns (commit for existing members, welcome for the new person)
    pub fn invite(
        &mut self,
        chat_id: &[u8],
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), VeilError> {
        let kp_in = wire!(KeyPackageIn::tls_deserialize_exact(key_package_bytes))?;
        let kp = mls!(kp_in.validate(self.provider.crypto(), ProtocolVersion::Mls10))?;
        let chat = self.chats.get_mut(chat_id).ok_or(VeilError::UnknownChat)?;
        let (commit, welcome, _info) =
            mls!(chat.add_members(&self.provider, &self.signer, &[kp]))?;
        mls!(chat.merge_pending_commit(&self.provider))?;
        Ok((
            wire!(commit.tls_serialize_detached())?,
            wire!(welcome.tls_serialize_detached())?,
        ))
    }

    pub fn join(&mut self, welcome_bytes: &[u8]) -> Result<Vec<u8>, VeilError> {
        let msg = wire!(MlsMessageIn::tls_deserialize_exact(welcome_bytes))?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(VeilError::Wire("expected a welcome".into()));
        };
        let staged = mls!(StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None, // ratchet tree rides inside the welcome
        ))?;
        let group = mls!(staged.into_group(&self.provider))?;
        let id = group.group_id().as_slice().to_vec();
        self.chats.insert(id.clone(), group);
        Ok(id)
    }

    pub fn send(&mut self, chat_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VeilError> {
        let chat = self.chats.get_mut(chat_id).ok_or(VeilError::UnknownChat)?;
        let msg = mls!(chat.create_message(&self.provider, &self.signer, plaintext))?;
        wire!(msg.tls_serialize_detached())
    }

    /// feed any incoming wire message (welcomes go to `join` instead).
    /// plaintext is None for protocol messages we handled internally
    pub fn recv(&mut self, wire_bytes: &[u8]) -> Result<Incoming, VeilError> {
        let msg = wire!(MlsMessageIn::tls_deserialize_exact(wire_bytes))?;
        let protocol_msg: ProtocolMessage = mls!(msg.try_into_protocol_message())?;
        let chat_id = protocol_msg.group_id().as_slice().to_vec();
        let chat = self
            .chats
            .get_mut(chat_id.as_slice())
            .ok_or(VeilError::UnknownChat)?;
        let processed = mls!(chat.process_message(&self.provider, protocol_msg))?;
        let sender = BasicCredential::try_from(processed.credential().clone())
            .map(|c| c.identity().to_vec())
            .unwrap_or_default();
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Some(app.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                mls!(chat.merge_staged_commit(&self.provider, *commit))?;
                None
            }
            _ => None,
        };
        Ok(Incoming {
            chat_id,
            sender,
            plaintext,
        })
    }

    pub fn chat_ids(&self) -> Vec<Vec<u8>> {
        self.chats.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_people_can_talk() {
        let mut alice = Client::new("alice").unwrap();
        let mut bob = Client::new("bob").unwrap();

        let chat = alice.create_chat().unwrap();
        let bob_kp = bob.key_package().unwrap();
        let (_commit, welcome) = alice.invite(&chat, &bob_kp).unwrap();
        let bob_chat = bob.join(&welcome).unwrap();
        assert_eq!(chat, bob_chat);

        let wire = alice.send(&chat, b"hey bob").unwrap();
        let got = bob.recv(&wire).unwrap();
        assert_eq!(got.plaintext.unwrap(), b"hey bob");
        assert_eq!(got.sender, b"alice");
        assert_eq!(got.chat_id, chat);

        // and back the other way
        let wire = bob.send(&bob_chat, b"yo").unwrap();
        let got = alice.recv(&wire).unwrap();
        assert_eq!(got.plaintext.unwrap(), b"yo");
        assert_eq!(got.sender, b"bob");
    }

    #[test]
    fn three_person_group() {
        let mut alice = Client::new("alice").unwrap();
        let mut bob = Client::new("bob").unwrap();
        let mut charlie = Client::new("charlie").unwrap();

        let chat = alice.create_chat().unwrap();
        let (_c, welcome) = alice.invite(&chat, &bob.key_package().unwrap()).unwrap();
        bob.join(&welcome).unwrap();

        // bob has to process the commit when charlie comes in
        let (commit, welcome) = alice.invite(&chat, &charlie.key_package().unwrap()).unwrap();
        assert!(bob.recv(&commit).unwrap().plaintext.is_none());
        charlie.join(&welcome).unwrap();

        let wire = alice.send(&chat, b"hi all").unwrap();
        assert_eq!(bob.recv(&wire).unwrap().plaintext.unwrap(), b"hi all");
        assert_eq!(charlie.recv(&wire).unwrap().plaintext.unwrap(), b"hi all");
    }

    #[test]
    fn tampered_ciphertext_dies() {
        let mut alice = Client::new("alice").unwrap();
        let mut bob = Client::new("bob").unwrap();
        let chat = alice.create_chat().unwrap();
        let (_c, welcome) = alice.invite(&chat, &bob.key_package().unwrap()).unwrap();
        bob.join(&welcome).unwrap();

        let mut wire = alice.send(&chat, b"secret").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;

        // openmls 0.6 fires a debug_assert (panic) on AEAD failure in debug
        // builds instead of returning Err — either way the tamper must not decrypt
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bob.recv(&wire)));
        match result {
            Ok(r) => assert!(r.is_err(), "tampered message must not decrypt"),
            Err(_) => {} // panic inside openmls = rejected, fine in debug profile
        }
    }

    #[test]
    fn server_never_sees_plaintext() {
        // the "server" only ever sees wire bytes — make sure plaintext isn't in there
        let mut alice = Client::new("alice").unwrap();
        let mut bob = Client::new("bob").unwrap();
        let chat = alice.create_chat().unwrap();
        let (_c, welcome) = alice.invite(&chat, &bob.key_package().unwrap()).unwrap();
        bob.join(&welcome).unwrap();

        let secret = b"super secret stuff nobody should read";
        let wire = alice.send(&chat, secret).unwrap();
        assert!(!wire.windows(secret.len()).any(|w| w == secret));
    }
}
