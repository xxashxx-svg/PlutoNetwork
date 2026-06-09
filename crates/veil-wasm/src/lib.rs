//! Thin wasm-bindgen wrapper around veil-core. No logic lives here —
//! just byte shuffling between JS and the Rust engine.

use veil_core::Client;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Invite {
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl Invite {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
pub struct VeilClient {
    inner: Client,
}

#[wasm_bindgen]
impl VeilClient {
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str) -> Result<VeilClient, JsError> {
        Ok(Self {
            inner: Client::new(name)?,
        })
    }

    pub fn key_package(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.key_package()?)
    }

    pub fn create_chat(&mut self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.create_chat()?)
    }

    pub fn invite(&mut self, chat_id: &[u8], key_package: &[u8]) -> Result<Invite, JsError> {
        let (commit, welcome) = self.inner.invite(chat_id, key_package)?;
        Ok(Invite { commit, welcome })
    }

    pub fn join(&mut self, welcome: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.join(welcome)?)
    }

    pub fn send(&mut self, chat_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.send(chat_id, plaintext)?)
    }

    /// plaintext is undefined for protocol messages we handled internally
    pub fn recv(&mut self, wire: &[u8]) -> Result<Incoming, JsError> {
        let inc = self.inner.recv(wire)?;
        Ok(Incoming {
            chat_id: inc.chat_id,
            sender: String::from_utf8_lossy(&inc.sender).into_owned(),
            plaintext: inc.plaintext,
        })
    }
}

#[wasm_bindgen]
pub struct Incoming {
    chat_id: Vec<u8>,
    sender: String,
    plaintext: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl Incoming {
    #[wasm_bindgen(getter, js_name = chatId)]
    pub fn chat_id(&self) -> Vec<u8> {
        self.chat_id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> String {
        self.sender.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Option<Vec<u8>> {
        self.plaintext.clone()
    }
}
