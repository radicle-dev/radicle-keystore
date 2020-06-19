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

pub use ed25519::*;

pub mod ed25519 {
    use std::{
        cmp::Ordering,
        convert::Infallible,
        fmt::{self, Debug},
        hash::{Hash, Hasher},
    };

    use sodiumoxide::utils;

    /// Ed25519 public key, encoded as per [RFC 8032]
    ///
    /// [RFC 8032]: https://tools.ietf.org/html/rfc8032
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct PublicKey(pub [u8; 32]);

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    /// Ed25519 signature, encoded as per [RFC 8032]
    ///
    /// [RFC 8032]: https://tools.ietf.org/html/rfc8032
    #[derive(Clone, Copy)]
    pub struct Signature(pub [u8; 64]);

    impl PartialEq for Signature {
        fn eq(&self, other: &Self) -> bool {
            utils::memcmp(&self.0, &other.0)
        }
    }

    impl Eq for Signature {}

    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Hash for Signature {
        fn hash<H: Hasher>(&self, state: &mut H) {
            Hash::hash(self.as_ref(), state)
        }
    }

    impl PartialOrd for Signature {
        #[inline]
        fn partial_cmp(&self, other: &Signature) -> Option<Ordering> {
            PartialOrd::partial_cmp(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn lt(&self, other: &Signature) -> bool {
            PartialOrd::lt(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn le(&self, other: &Signature) -> bool {
            PartialOrd::le(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn ge(&self, other: &Signature) -> bool {
            PartialOrd::ge(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn gt(&self, other: &Signature) -> bool {
            PartialOrd::gt(self.as_ref(), other.as_ref())
        }
    }

    impl Ord for Signature {
        #[inline]
        fn cmp(&self, other: &Signature) -> Ordering {
            Ord::cmp(self.as_ref(), other.as_ref())
        }
    }

    impl Debug for Signature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Signature({:?})", self.as_ref())
        }
    }

    #[async_trait]
    pub trait Signer {
        type Error;

        /// Obtain the [`PublicKey`] used for signing
        fn public_key(&self) -> PublicKey;

        /// Sign the supplied data with the secret key corresponding to
        /// [`Signer::public_key`]
        async fn sign(&self, data: &[u8]) -> Result<Signature, Self::Error>;
    }

    #[async_trait]
    impl Signer
        for (
            sodiumoxide::crypto::sign::ed25519::PublicKey,
            sodiumoxide::crypto::sign::ed25519::SecretKey,
        )
    {
        type Error = Infallible;

        fn public_key(&self) -> PublicKey {
            PublicKey((self.0).0)
        }

        async fn sign(&self, data: &[u8]) -> Result<Signature, Self::Error> {
            Ok(Signature(
                sodiumoxide::crypto::sign::ed25519::sign_detached(data, &self.1).0,
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use sodiumoxide::crypto::sign as sodium;

        const MESSAGE: &[u8] = b"in a bottle";

        /// Base compatibility test.
        ///
        /// Both the [`PublicKey`] and [`Signature`] produced by [`Signer`]
        /// implementations must be byte-for-byte equal.
        ///
        /// All combinatorial pairs of `Signer` implementations must pass this.
        async fn compat<S1, S2>(signer1: S1, signer2: S2)
        where
            S1: Signer,
            S2: Signer,

            S1::Error: Debug,
            S2::Error: Debug,
        {
            assert_eq!(signer1.public_key(), signer2.public_key());
            assert_eq!(
                signer1.sign(MESSAGE).await.unwrap(),
                signer2.sign(MESSAGE).await.unwrap()
            );
        }

        #[async_trait]
        impl Signer for ed25519_dalek::Keypair {
            type Error = Infallible;

            fn public_key(&self) -> PublicKey {
                PublicKey(self.public.to_bytes())
            }

            async fn sign(&self, data: &[u8]) -> Result<Signature, Self::Error> {
                let signer: &ed25519_dalek::Keypair = self;
                Ok(Signature(signer.sign(data).to_bytes()))
            }
        }

        #[async_std::test]
        async fn compat_sodium_dalek() {
            sodiumoxide::init().unwrap();

            let sodium = sodium::gen_keypair();
            let dalek = {
                let secret = ed25519_dalek::SecretKey::from_bytes(&sodium.1[..32]).unwrap();
                let public = ed25519_dalek::PublicKey::from(&secret);
                ed25519_dalek::Keypair { secret, public }
            };

            compat(sodium, dalek).await
        }
    }
}
