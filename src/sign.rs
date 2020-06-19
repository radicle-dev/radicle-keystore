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

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct PublicKey(pub [u8; 32]);

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

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

    pub trait Signer {
        type Error;

        /// Obtain the [`PublicKey`] used for signing
        fn public_key(&self) -> PublicKey;

        /// Sign the supplied data with the secret key corresponding to
        /// [`Signer::public_key`]
        fn sign(&self, data: &[u8]) -> Result<Signature, Self::Error>;
    }

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

        fn sign(&self, data: &[u8]) -> Result<Signature, Self::Error> {
            Ok(Signature(
                sodiumoxide::crypto::sign::ed25519::sign_detached(data, &self.1).0,
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use rand::rngs::OsRng;
        use sodiumoxide::crypto::sign as sodium;

        const MESSAGE: &[u8] = b"in a bottle";

        struct Roundtrip<S, V> {
            signer: S,
            verifier: V,
        }

        /// Base compatibility test.
        ///
        /// Given two `Signer` implementations, we assert that a signature
        /// produced by one can be verified by the other.
        ///
        /// All combinatorial pairs of `Signer` implementations should pass
        /// this.
        fn compat<S1, S2, V1, V2>(roundtrip1: Roundtrip<S1, V1>, roundtrip2: Roundtrip<S2, V2>)
        where
            S1: Signer,
            S2: Signer,
            V1: FnOnce(&Signature, &PublicKey) -> bool,
            V2: FnOnce(&Signature, &PublicKey) -> bool,

            S1::Error: Debug,
            S2::Error: Debug,
        {
            let sig1 = (roundtrip1.signer).sign(MESSAGE).unwrap();
            let sig2 = (roundtrip2.signer).sign(MESSAGE).unwrap();
            assert!(
                (roundtrip1.verifier)(&sig2, &(roundtrip2.signer).public_key()),
                "signature produced by signer1 could not be verified by signer2"
            );
            assert!(
                (roundtrip2.verifier)(&sig1, &(roundtrip1.signer).public_key()),
                "signature produced by signer2 could not be verified by signer1"
            );
        }

        /// We also demand that the byte representations of `PublicKey` and
        /// `Signature` be equal
        fn same_encoding<S1, S2>(signer1: S1, signer2: S2)
        where
            S1: Signer,
            S2: Signer,

            S1::Error: Debug,
            S2::Error: Debug,
        {
            assert_eq!(signer1.public_key(), signer2.public_key());
            assert_eq!(
                signer1.sign(MESSAGE).unwrap(),
                signer2.sign(MESSAGE).unwrap()
            );
        }

        impl Signer for ed25519_dalek::Keypair {
            type Error = Infallible;

            fn public_key(&self) -> PublicKey {
                PublicKey(self.public.to_bytes())
            }

            fn sign(&self, data: &[u8]) -> Result<Signature, Self::Error> {
                let signer: &ed25519_dalek::Keypair = self;
                Ok(Signature(signer.sign(data).to_bytes()))
            }
        }

        #[test]
        fn compat_sodium_dalek() {
            sodiumoxide::init().unwrap();
            compat(
                Roundtrip {
                    signer: sodium::gen_keypair(),
                    verifier: |sig: &Signature, pk: &PublicKey| {
                        let sig = sodium::Signature::from_slice(sig.as_ref())
                            .expect("does not look like a sodium ed25519 signature");
                        let pk = sodium::PublicKey::from_slice(pk.as_ref())
                            .expect("does not look like a sodium ed25519 public key");

                        sodium::verify_detached(&sig, MESSAGE, &pk)
                    },
                },
                Roundtrip {
                    signer: ed25519_dalek::Keypair::generate(&mut OsRng {}),
                    verifier: |sig: &Signature, pk: &PublicKey| {
                        let sig = ed25519_dalek::Signature::from_bytes(sig.as_ref()).unwrap();
                        let pk = ed25519_dalek::PublicKey::from_bytes(pk.as_ref()).unwrap();

                        pk.verify(MESSAGE, &sig).and(Ok(true)).unwrap()
                    },
                },
            )
        }

        #[test]
        fn same_encoding_sodium_dalek() {
            sodiumoxide::init().unwrap();

            let sodium = sodium::gen_keypair();
            let dalek = {
                let secret = ed25519_dalek::SecretKey::from_bytes(&sodium.1[..32]).unwrap();
                let public = ed25519_dalek::PublicKey::from(&secret);
                ed25519_dalek::Keypair { secret, public }
            };

            same_encoding(sodium, dalek)
        }
    }
}
