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

#[cfg(feature = "ssh-agent")]
use smol::{io, net::unix::UnixStream};

#[cfg(feature = "ssh-agent")]
fn main() -> io::Result<()> {
    use radicle_keystore::sign::{ssh, Signer, SshAgent};
    use rand::rngs::OsRng;

    smol::block_on(async {
        let sk = ed25519_zebra::SigningKey::new(OsRng {});
        let pk = ed25519_zebra::VerificationKey::from(&sk);
        let public = ssh::ed25519::PublicKey(pk.into());
        let agent = SshAgent::new(public);

        // This could be a `rad-ssh-add` executable which reads the local key from
        // the filestore (prompting for the password).
        ssh::add_key::<UnixStream>(&agent, sk, &[]).await.unwrap();

        println!("connecting to ssh-agent");
        let signer = agent
            .connect::<UnixStream>()
            .await
            .expect("could not connect to ssh-agent");
        println!("asking agent to sign some data");
        let sig = signer
            .sign(b"cooper")
            .await
            .expect("signing via ssh-agent failed");
        println!("verifying signature");
        pk.verify(&ed25519_zebra::Signature::from(sig.0), b"cooper")
            .expect("ssh-agent didn't return a valid signature");
        println!("it worksed");

        let keys = ssh::list_keys::<UnixStream>(&agent)
            .await
            .expect("could not list keys");
        if keys.contains(&public) {
            println!("added key succesfully")
        }
        ssh::remove_key::<UnixStream>(&agent, &public)
            .await
            .expect("could not remove key from ssh-agent");
        let keys = ssh::list_keys::<UnixStream>(&agent)
            .await
            .expect("could not list keys");
        if !keys.contains(&public) {
            println!("removed key successfully")
        }

        Ok(())
    })
}

#[cfg(not(feature = "ssh-agent"))]
fn main() {
    eprintln!("this example requires the `ssh-agent` feature")
}
