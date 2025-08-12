// use tls_codec::{TlsSerialize, TlsSize};


// //TODO: voir si le type tree_sumac::EncryptionKeyPair est vraiment nécessaire, et si on ne peut pas tout faire avec celui de treesync (qui est + pratique cr les fonctions de dérivations sont déjà définies pour eux)

// #[derive(Clone)]
// pub struct HPKEEncryptionKeyPair {
//     pub public: HpkePublicKey,
//     pub private: HpkePrivateKey,
// }

// impl From<openmls_traits::types::HpkeKeyPair> for HPKEEncryptionKeyPair {
//     fn from(value: openmls_traits::types::HpkeKeyPair) -> Self {
//         Self {
//             public: HpkePublicKey { key: value.public },
//             private: value.private.into(),
//         }
//     }
// }

// impl Into<openmls::tree_sumac::EncryptionKeyPair> for HPKEEncryptionKeyPair {
//     fn into(self) -> openmls::tree_sumac::EncryptionKeyPair {
//         let x: openmls::tree_sumac::EncryptionKey = self.public.into();
//         let y: openmls::tree_sumac::EncryptionPrivateKey = self.private.into();

//         openmls::tree_sumac::EncryptionKeyPair::from(
//             (
//                 x, y
//             )
//         )
//     }
// }

// #[derive(Debug, Clone, TlsSize, TlsSerialize)]
// pub struct HpkePublicKey {
//     key: Vec<u8>,
// }

// impl From<Vec<u8>> for HpkePublicKey {
//     fn from(value: Vec<u8>) -> Self {
//         Self { key: value }
//     }
// }

// impl From<openmls::tree_sumac::EncryptionKey> for HpkePublicKey {
//     fn from(value: openmls::tree_sumac::EncryptionKey) -> Self {
//         Self {
//             key: value.as_slice().to_vec(),
//         }
//     }
// }

// impl Into<openmls::tree_sumac::EncryptionKey> for HpkePublicKey {
//     fn into(self) -> openmls::tree_sumac::EncryptionKey {
//         openmls::tree_sumac::EncryptionKey::from(self.key)
//     }
// }

// impl Into<Vec<u8>> for HpkePublicKey {
//     fn into(self) -> Vec<u8> {
//         self.key
//     }
// }

// #[derive(Clone)]
// pub struct HpkePrivateKey {
//     key: Vec<u8>,
// }

// impl From<openmls_traits::types::HpkePrivateKey> for HpkePrivateKey {
//     fn from(value: openmls_traits::types::HpkePrivateKey) -> Self {
//         Self {
//             key: value.to_vec(),
//         }
//     }
// }

// impl From<openmls::tree_sumac::EncryptionPrivateKey> for HpkePrivateKey {
//     fn from(value: openmls::tree_sumac::EncryptionPrivateKey) -> Self {
//         Self {
//             key: value.as_vec(),
//         }
//     }
// }

// impl Into<openmls_traits::types::HpkePrivateKey> for HpkePrivateKey {
//     fn into(self) -> openmls_traits::types::HpkePrivateKey {
//         openmls_traits::types::HpkePrivateKey::from(self.key)
//     }
// }

// impl Into<openmls::tree_sumac::EncryptionPrivateKey> for HpkePrivateKey {
//     fn into(self) -> openmls::tree_sumac::EncryptionPrivateKey {
//         openmls::tree_sumac::EncryptionPrivateKey::from(self.key)
//     }
// }

use openmls::tree_sumac::nodes::encryption_keys::{PkeKeyPair, PkePrivateKey, PkePublicKey};


pub type HPKEEncryptionKeyPair = PkeKeyPair;
pub type HPKEPrivateKey = PkePrivateKey;
pub type HPKEPublicKey = PkePublicKey;
