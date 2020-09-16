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

/// Work factor for scrypt.
///
/// The current value of `16` is secure for production uses but too slow for
/// tests. Therefore, we use a lower value for testing.
#[cfg(not(test))]
const SCRYPT_WORK_FACTOR: u8 = 16;
#[cfg(test)]
const SCRYPT_WORK_FACTOR: u8 = 4;

/// Nonce used for secret box.
type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// 192-bit salt.
type Salt = [u8; 24];

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
pub struct SecretBox<C>
where
    C: aead::Aead,
{
    nonce: Nonce<C::NonceSize>,
    salt: Salt,
    sealed: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SecretBoxError<PinentryError: std::error::Error + 'static> {
    #[error("Unable to decrypt secret box using the derived key")]
    InvalidKey,

    #[error("Error getting passphrase")]
    Pinentry(#[from] PinentryError),
}

/// A [`Crypto`] implementation using `libsodium`'s "secretbox". The encryption
/// key is derived from a passphrase using the primitives provided by
/// `libsodium`'s `pwhash` (hence the name).
///
/// The resulting [`SecretBox`] stores the ciphertext alongside cleartext salt
/// and nonce values.
#[derive(Clone)]
pub struct Pwhash<P> {
    pinentry: P,
}

impl<P> Pwhash<P> {
    /// Create a new [`Pwhash`] value
    ///
    /// Panics if the `sodiumoxide` crate could not be initialised.
    pub fn new(pinentry: P) -> Self {
        Self { pinentry }
    }
}

impl<P> Crypto for Pwhash<P>
where
    P: Pinentry,
    P::Error: std::error::Error + 'static,
{
    type SecretBox = SecretBox<chacha20poly1305::ChaCha20Poly1305>;
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
        let mut salt: Salt = [0; 24];
        rng.fill_bytes(&mut salt);

        // Derive key from passphrase.
        let nonce = *Nonce::from_slice(&nonce[..]);
        let derived = derive_key(&salt, &passphrase);
        let key = chacha20poly1305::Key::from_slice(&derived[..]);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

        let sealed = cipher.encrypt(&nonce, secret.as_ref()).unwrap();

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

        let derived = derive_key(&secret_box.salt, &passphrase);
        let key = chacha20poly1305::Key::from_slice(&derived[..]);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

        cipher
            .decrypt(&secret_box.nonce, secret_box.sealed.as_slice())
            .map_err(|_| SecretBoxError::InvalidKey)
            .map(SecStr::new)
    }
}

fn derive_key(salt: &Salt, passphrase: &SecUtf8) -> [u8; 32] {
    let mut key = [0u8; 32];
    let params = crypto::scrypt::ScryptParams::new(SCRYPT_WORK_FACTOR, 8, 1);
    crypto::scrypt::scrypt(passphrase.unsecure().as_bytes(), salt, &params, &mut key);

    key
}
