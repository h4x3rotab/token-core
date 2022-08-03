use iop_keyvault::ed25519::{Ed25519, EdExtPrivateKey, EdPublicKey};
use iop_keyvault::{
    ChildIndex, ExtendedPrivateKey, KeyDerivationCrypto, PrivateKey as iop_keyvault_private_key,
    Seed,
};

use super::Result;
use crate::ecc::KeyError;
use crate::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::{
    Derive, DeterministicPrivateKey, DeterministicPublicKey, FromHex, PrivateKey, PublicKey, ToHex,
};
use bip39::{Language, Mnemonic};

pub struct Ed25519DeterministicPrivateKey(EdExtPrivateKey);

pub struct Ed25519DeterministicPublicKey(EdPublicKey);

impl Ed25519DeterministicPrivateKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed_obj = Seed::from_bytes(&seed).unwrap();
        let master = Ed25519::master(&seed_obj);
        Ok(Ed25519DeterministicPrivateKey(master))
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        Ok(Self::from_seed(seed.as_ref())?)
    }
}

impl Derive for Ed25519DeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let mut extended_key = self.0.clone();

        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }

        let (mut successes, errors): (Vec<_>, Vec<_>) = parts
            .map(|p: &str| (p, p.parse::<ChildIndex>()))
            .partition(|(_p, i)| i.is_ok());
        if !errors.is_empty() {
            return Err(KeyError::InvalidDerivationPathFormat.into());
        }
        let child_index_vec: Vec<ChildIndex> =
            successes.drain(..).map(|(_p, i)| i.unwrap()).collect();

        for child_number in child_index_vec {
            let chain_index = match child_number {
                ChildIndex::Normal(_index) => {
                    return Err(KeyError::UnsupportNormalDerivation.into());
                }
                ChildIndex::Hardened(index) => index,
            };
            extended_key = extended_key.derive_hardened_child(chain_index).unwrap();
        }

        Ok(Ed25519DeterministicPrivateKey(extended_key))
    }
}

impl Derive for Ed25519DeterministicPublicKey {
    fn derive(&self, _path: &str) -> Result<Self> {
        Err(KeyError::UnsupportEd25519PubkeyDerivation.into())
    }
}

impl DeterministicPrivateKey for Ed25519DeterministicPrivateKey {
    type DeterministicPublicKey = Ed25519DeterministicPublicKey;
    type PrivateKey = Ed25519PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed_obj = Seed::from_bytes(&seed).unwrap();
        let master = Ed25519::master(&seed_obj);
        Ok(Ed25519DeterministicPrivateKey(master))
    }

    fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        Ok(Self::from_mnemonic(mnemonic).unwrap())
    }

    fn private_key(&self) -> Self::PrivateKey {
        Ed25519PrivateKey::from_slice(self.0.private_key().to_bytes().as_slice()).unwrap()
    }

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey {
        Ed25519DeterministicPublicKey(self.0.private_key().public_key())
    }
}

impl DeterministicPublicKey for Ed25519DeterministicPublicKey {
    type PublicKey = Ed25519PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey::from_slice(self.0.to_bytes().as_slice()).unwrap()
    }
}

impl ToString for Ed25519DeterministicPrivateKey {
    fn to_string(&self) -> String {
        hex::encode(self.0.private_key().to_bytes())
    }
}

impl ToString for Ed25519DeterministicPublicKey {
    fn to_string(&self) -> String {
        hex::encode(self.0.to_bytes())
    }
}

impl ToHex for Ed25519DeterministicPublicKey {
    fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl FromHex for Ed25519DeterministicPublicKey {
    fn from_hex(_hex: &str) -> Result<Self> {
        Err(KeyError::UnsupportEd25519PubkeyDerivation.into())
    }
}

#[cfg(test)]
mod test {
    use crate::ed25519_bip32::Ed25519DeterministicPrivateKey;
    use crate::Derive;
    use bip39::{Language, Mnemonic, Seed};
    use hex;
    use iop_keyvault::{ExtendedPrivateKey, PrivateKey};

    fn default_seed() -> Seed {
        let mn = Mnemonic::from_phrase(
            "club behind enforce pitch analyst blossom skull entry occur speak hotel clever",
            Language::English,
        )
        .unwrap();
        Seed::new(&mn, "")
    }

    #[test]
    fn from_seed_test() {
        let mn = "club behind enforce pitch analyst blossom skull entry occur speak hotel clever";
        //let seed = hex::decode("402f44cbd9a2070a20f58abdcbc1b1662863cd2ba2d941fe78ff934fdedffc293214c93364c6d37403b3d59d91589efb8ff8ecfa1642dafda451a34b397d1499").unwrap();
        //        println!("{}", hex::encode(default_seed().as_bytes()));
        //master key
        //let esk = Ed25519DeterministicPrivateKey::from_seed(&seed).unwrap();

        let esk = Ed25519DeterministicPrivateKey::from_mnemonic(mn).unwrap();
        println!("root sk: {}",
            hex::encode(esk.0.private_key().to_bytes())
        );
        println!("root pk: {}",
            hex::encode(esk.0.chain_code().to_bytes())
        );

        let paths = [
            "m/44'/354'",
            "m/44'/354'/0'",
            "m/44'/354'/0'/0'",
            "m/44'/354'/0'/0'/0'",
            "m/44'/354'/0'/0'/0'/0'",
            "m/44'/434'",
            "m/44'/434'/0'",
            "m/44'/434'/0'/0'",
            "m/44'/434'/0'/0'/0'",
            "m/44'/434'/0'/0'/0'/0'",
        ];

        for path in &paths {
            let derived_result = esk.derive(path).unwrap().0;
            println!(
                "{}, {}, {}",
                hex::encode(derived_result.private_key().to_bytes()),
                hex::encode(derived_result.chain_code().to_bytes()),
                path,
            );
        }

        /*
        //extended key
        let path = "m/44'/354'";
        let derived_result = esk.derive(path).unwrap().0;
        //assert_eq!(
        //    "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
        //    hex::encode(derived_result.private_key().to_bytes())
        //);
        assert_eq!(
            "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
            hex::encode(derived_result.chain_code().to_bytes())
        );
        */
    }
}
