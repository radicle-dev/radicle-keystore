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

use futures::lock::Mutex;
use thrussh_keys::{
    agent::client::AgentClient,
    encoding::Encoding as _,
    key::{parse_public_key, KeyPair, PublicKey},
    signature::{Signature, SignatureBytes},
    Error as ClientError,
};
use tokio::net::UnixStream;

pub use super::ed25519;
pub use thrussh_keys::{
    agent::Constraint,
    key::{ed25519::SecretKey, SignatureHash},
};

pub mod error {
    use super::*;
    use thiserror::Error;

    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum Connect {
        #[error(transparent)]
        Client(#[from] ClientError),
    }

    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum AddKey {
        #[error(transparent)]
        Client(#[from] ClientError),
    }

    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum Sign {
        #[error("for some reason the agent returned an RSA signature")]
        Rsa { hash: SignatureHash, bytes: Vec<u8> },

        #[error(transparent)]
        Client(#[from] ClientError),
    }
}

/// A [`ed25519::Signer`] backed by an `ssh-agent`.
///
/// A connection to the agent needs to be established via [`SshAgent::connect`].
/// Due to implementation limitations, the only way to connect is currently via
/// the unix domain socket whose path is read from the `SSH_AUTH_SOCK`
/// environment variable.
pub struct SshAgent(ed25519::PublicKey);

impl SshAgent {
    pub fn new(key: ed25519::PublicKey) -> Self {
        Self(key)
    }

    pub async fn connect(
        self,
    ) -> Result<impl ed25519::Signer<Error = error::Sign>, error::Connect> {
        let client = AgentClient::connect_env()
            .await
            .map(|client| Mutex::new(Some(client)))?;
        let ssh = {
            let mut pk = Vec::new();
            pk.extend_ssh_string(b"ssh-ed25519");
            pk.extend_ssh_string(self.0.as_ref());
            parse_public_key(&pk)?
        };

        Ok(Signer {
            rfc: self.0,
            ssh,
            client,
        })
    }
}

// `AgentClient::sign_request_signature` returns `Result<(Self, Signature),
// Error>` instead of `(Self, Result<Signature, Error>)`, which is probably a
// bug. Because of this (and the move semantics, which are a bit weird anyways),
// we need to slap our own mutex, and reconnect if we get an error.
type Client = Mutex<Option<AgentClient<UnixStream>>>;

struct Signer {
    rfc: ed25519::PublicKey,
    ssh: PublicKey,
    client: Client,
}

/// Add a secret key to a running ssh-agent.
///
/// Connects to the agent via the `SSH_AUTH_SOCK` unix domain socket.
pub async fn add_key(secret: SecretKey, constraints: &[Constraint]) -> Result<(), error::AddKey> {
    let mut client = AgentClient::connect_env().await?;
    client
        .add_identity(&KeyPair::Ed25519(secret), constraints)
        .await?;

    Ok(())
}

#[async_trait]
impl ed25519::Signer for Signer {
    type Error = error::Sign;

    fn public_key(&self) -> ed25519::PublicKey {
        self.rfc
    }

    async fn sign(&self, data: &[u8]) -> Result<ed25519::Signature, Self::Error> {
        let mut guard = self.client.lock().await;
        let client = match guard.take() {
            None => AgentClient::connect_env().await?,
            Some(client) => client,
        };

        let (client, sig) = client.sign_request_signature(&self.ssh, data).await?;
        *guard = Some(client);
        match sig {
            Signature::Ed25519(SignatureBytes(bytes)) => Ok(ed25519::Signature(bytes)),
            Signature::RSA { hash, bytes } => Err(error::Sign::Rsa { hash, bytes }),
        }
    }
}
