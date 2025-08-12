use std::fmt;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::CryptoError,
    types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair},
};
use tls_codec::VLBytes;
use tls_codec::{Serialize, TlsSerialize, TlsSize};

use crate::{
    ciphersuite::{hpke, HpkePrivateKey, HpkePublicKey},
    error::LibraryError,
    prelude::{aead, AeadKey, AeadNonce, PathSecret, Secret},
};

////// Types for HPKE Encryption ////////

#[derive(Clone, Debug, Eq, PartialEq, TlsSize, TlsSerialize)]
pub struct PkePublicKey {
    key: HpkePublicKey,
}

impl PkePublicKey {
    /// Return the internal [`HpkePublicKey`].
    pub(crate) fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    /// Return the internal [`HpkePublicKey`] as slice.
    pub fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Encrypt to this HPKE public key.
    pub fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, LibraryError> {
        hpke::encrypt_with_label(
            self.as_slice(),
            "UpdatePathNode",
            &[],
            plaintext,
            ciphersuite,
            crypto,
        )
        .map_err(|_| LibraryError::custom("Encryption failed. A serialization issue really"))
    }
}

impl From<Vec<u8>> for PkePublicKey {
    fn from(key: Vec<u8>) -> Self {
        Self { key: key.into() }
    }
}

impl From<HpkePublicKey> for PkePublicKey {
    fn from(key: HpkePublicKey) -> Self {
        Self { key }
    }
}

#[derive(Clone, Debug)]
pub struct PkePrivateKey {
    key: HpkePrivateKey,
}

impl From<Vec<u8>> for PkePrivateKey {
    fn from(key: Vec<u8>) -> Self {
        Self { key: key.into() }
    }
}

impl From<HpkePrivateKey> for PkePrivateKey {
    fn from(key: HpkePrivateKey) -> Self {
        Self { key }
    }
}

impl PkePrivateKey {
    /// Decrypt a given `HpkeCiphertext` using this [`EncryptionPrivateKey`] and
    /// `group_context`.
    ///
    /// Returns the decrypted [`Secret`]. Returns an error if the decryption was
    /// unsuccessful.
    pub fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &HpkeCiphertext,
    ) -> Result<PathSecret, LibraryError> {
        // ValSem203: Path secrets must decrypt correctly
        hpke::decrypt_with_label(
            &self.key,
            "UpdatePathNode",
            &[],
            ciphertext,
            ciphersuite,
            crypto,
        )
        .map_err(|_| LibraryError::unexpected_crypto_error(CryptoError::HpkeDecryptionError))
        .map(|secret_bytes| PathSecret::from(Secret::from_slice(&secret_bytes)))
    }


    pub fn decrypt_raw(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>, LibraryError> {
        // ValSem203: Path secrets must decrypt correctly
        hpke::decrypt_with_label(
            &self.key,
            "UpdatePathNode",
            &[],
            ciphertext,
            ciphersuite,
            crypto,
        )
        .map_err(|_| LibraryError::unexpected_crypto_error(CryptoError::HpkeDecryptionError))
    }

    pub fn as_vec(&self) -> Vec<u8> {
        self.key.to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct PkeKeyPair {
    public_key: PkePublicKey,
    private_key: PkePrivateKey,
}

impl PkeKeyPair {
    // Here implement the storage provider read/write/delete ?

    pub fn as_tuple(&self) -> (&PkePublicKey, &PkePrivateKey) {
        (&self.public_key, &self.private_key)
    }

    pub fn random(
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, LibraryError> {
        let ikm =
            Secret::random(ciphersuite, rand).map_err(LibraryError::unexpected_crypto_error)?;
        Ok(crypto
            .derive_hpke_keypair(ciphersuite.hpke_config(), ikm.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?
            .into())
    }

    pub(crate) fn derive_from_path_secret(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path_secret: &PathSecret,
    ) -> Result<Self, LibraryError> {
        let node_secret = path_secret
            .clone()
            .secret()
            .kdf_expand_label(crypto, ciphersuite, "node", &[], ciphersuite.hash_length())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let HpkeKeyPair { public, private } = crypto
            .derive_hpke_keypair(ciphersuite.hpke_config(), node_secret.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?;

        Ok((HpkePublicKey::from(public), private).into())
    }
}

impl From<(HpkePublicKey, HpkePrivateKey)> for PkeKeyPair {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }
}

impl From<HpkeKeyPair> for PkeKeyPair {
    fn from(hpke_keypair: HpkeKeyPair) -> Self {
        let public_bytes: VLBytes = hpke_keypair.public.into();
        let private_bytes = hpke_keypair.private;
        Self {
            public_key: public_bytes.into(),
            private_key: private_bytes.into(),
        }
    }
}

impl From<(PkePublicKey, PkePrivateKey)> for PkeKeyPair {
    fn from((public_key, private_key): (PkePublicKey, PkePrivateKey)) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

impl Into<(PkePublicKey, PkePrivateKey)> for PkeKeyPair {
    fn into(self) -> (PkePublicKey, PkePrivateKey) {
        (self.public_key, self.private_key)
    }
}

pub trait KeyPairRef<PK, SK> {
    fn public_key(&self) -> &PK;
    fn private_key(&self) -> &SK;
}

impl KeyPairRef<PkePublicKey, PkePrivateKey> for PkeKeyPair {
    fn public_key(&self) -> &PkePublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &PkePrivateKey {
        &self.private_key
    }
}

// This is just to use the same abstraction for all trees. It is not particularly meaningful
impl KeyPairRef<SymmetricKey, SymmetricKey> for SymmetricKey{
    fn public_key(&self) -> &SymmetricKey {
        &self
    }

    fn private_key(&self) -> &SymmetricKey {
        &self
    }
}

////// Types for Symmetric Encryption Encryption ////////

#[derive(Clone, Eq, PartialEq, Debug, TlsSize, TlsSerialize)]
pub struct SymmetricKey {
    pub(crate) key: AeadKey,
}

pub(crate) type AeadCiphertext = Vec<u8>;

impl SymmetricKey {
    /// Return the internal [`AeadKey`].
    pub(crate) fn key(&self) -> &AeadKey {
        &self.key
    }

    /// Encrypt to this SK public key.
    pub fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        plaintext: &[u8],
    ) -> Result<AeadCiphertext, LibraryError> {
        self.key
            .aead_seal(
                crypto,
                plaintext,
                &[],
                &AeadNonce::default()
            )
            .map_err(|err| LibraryError::unexpected_crypto_error(err))
    }

    /// Decrypt to this SK public key.
    pub fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &AeadCiphertext,
    ) -> Result<AeadCiphertext, LibraryError> {
        self.key
            .aead_open(
                crypto,
                ciphertext.as_slice(),
                &[],
                &AeadNonce::default(),
            )
            .map_err(|err| LibraryError::unexpected_crypto_error(err))
    }

    pub fn derive_from_path_secret(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path_secret: &PathSecret,
    ) -> Result<Self, LibraryError> {
        path_secret
            .clone()
            .secret()
            .hkdf_expand(
                crypto,
                ciphersuite,
                "enc".as_bytes(),
                ciphersuite.aead_key_length(),
            )
            .map(|secret| Self::from(AeadKey::from_secret(secret, ciphersuite)))
            .map_err(|e| LibraryError::unexpected_crypto_error(e))
    }

    pub(crate) fn zero(ciphersuite : Ciphersuite) -> Self{
        Self { key: AeadKey::from_secret(Secret::zero(ciphersuite), ciphersuite) }
    }
}

impl From<AeadKey> for SymmetricKey {
    fn from(key: AeadKey) -> Self {
        Self { key }
    }
}

impl From<(SymmetricKey, SymmetricKey)> for SymmetricKey {
    fn from(value: (SymmetricKey, SymmetricKey)) -> Self {
        assert_eq!(value.0, value.1);
        value.0
    }
}

impl From<SymmetricKey> for (SymmetricKey, SymmetricKey) {
    fn from(k: SymmetricKey) -> Self {
        (k.clone(), k)
    }
}
