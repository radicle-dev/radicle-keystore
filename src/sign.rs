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
        fn sign(&mut self, data: &[u8]) -> Result<Signature, Self::Error>;
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

        fn sign(&mut self, data: &[u8]) -> Result<Signature, Self::Error> {
            Ok(Signature(
                sodiumoxide::crypto::sign::ed25519::sign_detached(data, &self.1).0,
            ))
        }
    }
}
