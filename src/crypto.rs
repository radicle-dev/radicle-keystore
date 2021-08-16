// This file is part of radicle-link
// <https://github.com/radicle-dev/radicle-link>
//
// Copyright (C) 2019-2020 The Radicle Team <dev@radicle.xyz>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 or
// later as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use chacha20poly1305::{
    aead,
    aead::{Aead, NewAead},
};
use generic_array::GenericArray;
use secstr::{SecStr, SecUtf8};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pinentry::Pinentry;

/// Parameters for the key derivation function.
pub type KdfParams = scrypt::ScryptParams;

lazy_static! {
    /// [`KdfParams`] suitable for production use.
    pub static ref KDF_PARAMS_PROD: KdfParams = scrypt::ScryptParams::new(15, 8, 1).unwrap();

    /// [`KdfParams`] suitable for use in tests.
    ///
    /// # Warning
    ///
    /// These parameters allows a brute-force attack against an encrypted
    /// [`SecretBox`] to be carried out at significantly lower cost. Care must
    /// be taken by users of this library to prevent accidental use of test
    /// parameters in a production setting.
    pub static ref KDF_PARAMS_TEST: KdfParams = scrypt::ScryptParams::new(4, 8, 1).unwrap();
}

/// Nonce used for secret box.
type Nonce = GenericArray<u8, <chacha20poly1305::ChaCha20Poly1305 as aead::Aead>::NonceSize>;

/// Size of the salt, in bytes.
const SALT_SIZE: usize = 24;

/// 192-bit salt.
type Salt = [u8; SALT_SIZE];

/// Class of types which can seal (encrypt) a secret, and unseal (decrypt) it
/// from it's sealed form.
///
/// It is up to the user to perform conversion from and to domain types.
pub trait Crypto: Sized {
    type SecretBox;
    type Error;

    fn seal<K: AsRef<[u8]>>(&self, secret: K) -> Result<Self::SecretBox, Self::Error>;
    fn unseal(&self, secret_box: Self::SecretBox) -> Result<SecStr, Self::Error>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretBox {
    nonce: Nonce,
    salt: Salt,
    sealed: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SecretBoxError<PinentryError: std::error::Error + 'static> {
    #[error("Unable to decrypt secret box using the derived key")]
    InvalidKey,

    #[error("Error returned from underlying crypto")]
    CryptoError,

    #[error("Error getting passphrase")]
    Pinentry(#[from] PinentryError),
}

/// A [`Crypto`] implementation based on `libsodium`'s "secretbox".
///
/// While historically based on `libsodium`, the underlying implementation is
/// now based on the [`chacha20poly1305`] crate. The encryption key is derived
/// from a passphrase using [`scrypt`].
///
/// The resulting [`SecretBox`] stores the ciphertext alongside cleartext salt
/// and nonce values.
#[derive(Clone)]
pub struct Pwhash<P> {
    pinentry: P,
    params: KdfParams,
}

impl<P> Pwhash<P> {
    /// Create a new [`Pwhash`] value
    pub fn new(pinentry: P, params: KdfParams) -> Self {
        Self { pinentry, params }
    }
}

impl<P> Crypto for Pwhash<P>
where
    P: Pinentry,
    P::Error: std::error::Error + 'static,
{
    type SecretBox = SecretBox;
    type Error = SecretBoxError<P::Error>;

    fn seal<K: AsRef<[u8]>>(&self, secret: K) -> Result<Self::SecretBox, Self::Error> {
        use rand::RngCore;

        let passphrase = self
            .pinentry
            .get_passphrase()
            .map_err(SecretBoxError::Pinentry)?;

        let mut rng = rand::thread_rng();

        // Generate nonce.
        let mut nonce = [0; 12];
        rng.fill_bytes(&mut nonce);

        // Generate salt.
        let mut salt: Salt = [0; SALT_SIZE];
        rng.fill_bytes(&mut salt);

        // Derive key from passphrase.
        let nonce = *Nonce::from_slice(&nonce[..]);
        let derived = derive_key(&salt, &passphrase, &self.params);
        let key = chacha20poly1305::Key::from_slice(&derived[..]);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

        let sealed = cipher
            .encrypt(&nonce, secret.as_ref())
            .map_err(|_| Self::Error::CryptoError)?;

        Ok(SecretBox {
            nonce,
            salt,
            sealed,
        })
    }

    fn unseal(&self, secret_box: Self::SecretBox) -> Result<SecStr, Self::Error> {
        let passphrase = self
            .pinentry
            .get_passphrase()
            .map_err(SecretBoxError::Pinentry)?;

        let derived = derive_key(&secret_box.salt, &passphrase, &self.params);
        let key = chacha20poly1305::Key::from_slice(&derived[..]);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

        cipher
            .decrypt(&secret_box.nonce, secret_box.sealed.as_slice())
            .map_err(|_| SecretBoxError::InvalidKey)
            .map(SecStr::new)
    }
}

fn derive_key(salt: &Salt, passphrase: &SecUtf8, params: &scrypt::ScryptParams) -> [u8; 32] {
    let mut key = [0u8; 32];
    scrypt::scrypt(passphrase.unsecure().as_bytes(), salt, params, &mut key)
        .expect("Output length must not be zero");

    key
}
