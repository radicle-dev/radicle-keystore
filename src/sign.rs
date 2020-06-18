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

use std::convert::Infallible;

use sodiumoxide::crypto::sign::ed25519;

use crate::Keypair;
#[cfg(feature = "ssh")]
pub use ssh::*;

pub trait Signer {
    type PublicKey;
    type Signature;

    type Error;

    fn public_key(&self) -> &Self::PublicKey;
    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature, Self::Error>;
}

impl Signer for Keypair<ed25519::PublicKey, ed25519::SecretKey> {
    type PublicKey = ed25519::PublicKey;
    type Signature = ed25519::Signature;

    type Error = Infallible;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn sign(&mut self, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        Ok(ed25519::sign_detached(data, &self.secret_key))
    }
}

#[cfg(feature = "ssh")]
mod ssh {
    use super::*;

    use std::cell::RefCell;

    pub use cryptovec::CryptoVec;
    use futures::executor::block_on;
    use thrussh_keys::agent::client::AgentClient;
    use tokio::io::{AsyncRead, AsyncWrite};

    pub struct SshAgent<S: AsyncRead + AsyncWrite> {
        public_key: thrussh_keys::key::PublicKey,
        client: RefCell<Option<AgentClient<S>>>,
    }

    impl<S: AsyncRead + AsyncWrite> SshAgent<S> {
        pub fn new<K: Into<thrussh_keys::key::PublicKey>>(
            public_key: K,
            client: AgentClient<S>,
        ) -> Self {
            Self {
                public_key: public_key.into(),
                client: RefCell::new(Some(client)),
            }
        }
    }

    impl<S> Signer for SshAgent<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        type PublicKey = thrussh_keys::key::PublicKey;
        type Signature = CryptoVec;
        type Error = anyhow::Error;

        fn public_key(&self) -> &Self::PublicKey {
            &self.public_key
        }

        fn sign(&mut self, data: &[u8]) -> Result<Self::Signature, Self::Error> {
            match self.client.replace(None) {
                Some(client) => {
                    self.client.replace(None);
                    let data = CryptoVec::from(Vec::from(data));
                    let (client, result) = block_on(client.sign_request(&self.public_key, data));
                    let _ = self.client.replace(Some(client));
                    result
                },
                None => unreachable!(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use std::future::Future;

        use tempfile::tempdir;
        use thrussh_keys::*;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {
            fn confirm(
                self,
                _: std::sync::Arc<key::KeyPair>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
                Box::new(futures::future::ready((self, true)))
            }
        }

        const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE\n0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2\nMpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx\nIkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY\nj346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/\nP8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds\nTcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7\njX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU\nkvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof\nYhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb\nXv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa\nZ80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML\nUw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl\no/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE\nQF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+\nN8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ\nRN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ\nrAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2\nzwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5\nnq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub\n5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/\nT0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e\nYIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK\n/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6\nb1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr\nJkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc\nCog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux\n-----END ENCRYPTED PRIVATE KEY-----\n";

        #[test]
        fn test_sign() {
            let tmp = tempdir().unwrap();
            let agent_path = tmp.path().join("agent");

            let mut rt = tokio::runtime::Runtime::new().unwrap();

            let agent_path_ = agent_path.clone();

            // Starting a server
            rt.spawn(async move {
                let mut listener = tokio::net::UnixListener::bind(&agent_path_).unwrap();
                thrussh_keys::agent::server::serve(listener.incoming(), X {}).await
            });

            let key = decode_secret_key(PKCS8_ENCRYPTED, Some(b"blabla")).unwrap();
            let public = key.clone_public_key();

            let res = rt
                .block_on(async move {
                    let stream = tokio::net::UnixStream::connect(&agent_path).await?;
                    let mut client = agent::client::AgentClient::connect(stream);
                    client
                        .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }])
                        .await?;
                    client.request_identities().await?;

                    let mut agent_signer = SshAgent::new(public, client);

                    let buf = b"signed message";
                    let sig = agent_signer.sign(buf).unwrap();
                    println!("{:?}", sig);

                    Ok::<bool, anyhow::Error>(
                        agent_signer.public_key().verify_detached(buf, sig.as_ref()),
                    )
                })
                .unwrap();

            assert!(res)
        }
    }
}
