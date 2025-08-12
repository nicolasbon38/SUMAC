use openmls::{
    prelude::{
        Ciphersuite, CredentialWithKey, CryptoError, Signable, Signature, SignedStruct
    }, tree_sumac::{nodes::encryption_keys::KeyPairRef, LeafNodeCGKA, LeafNodeTMKA}}
;
use openmls_traits::{signatures::Signer, OpenMlsProvider};
use tls_codec::{Serialize, TlsSerialize, TlsSize};


use crate::{crypto::{hpke::derive_hpke_keypair, secret::Secret, types::{HPKEEncryptionKeyPair, HPKEPublicKey}}, errors::SumacError};


#[derive(Clone, TlsSize, TlsSerialize)]
pub struct KeyPackageTbsPayload {
    ciphersuite: Ciphersuite,
    leaf_node_cgka: LeafNodeCGKA,
    leaf_node_tmka : LeafNodeTMKA,
    public_key: HPKEPublicKey,
}

const SIGNATURE_KEY_PACKAGE_LABEL: &str = "KeyPackageTBS";
impl Signable for KeyPackageTbsPayload {
    type SignedOutput = KeyPackage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

#[derive(Clone)]
pub struct KeyPackage {
    payload: KeyPackageTbsPayload,
    signature: Signature,
}
impl SignedStruct<KeyPackageTbsPayload> for KeyPackage{
    fn from_payload(payload: KeyPackageTbsPayload, signature: Signature) -> Self {
        Self { payload, signature }

    }
}

pub struct KeyPackageCreationResult {
    pub key_package: KeyPackage,
    pub encryption_keypair: HPKEEncryptionKeyPair,
}

impl KeyPackage {
    // Returns the key package, as well as the keypair that contains the corresponding private key
    pub fn create(
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        signer: &impl Signer,
        credential_with_key: &CredentialWithKey,
    ) -> Result<KeyPackageCreationResult, SumacError> {
        if ciphersuite.signature_algorithm() != signer.signature_scheme() {
            return Err(SumacError::CryptoError(
                CryptoError::UnsupportedSignatureScheme,
            ));
        }

        // Create a new HPKE key pair
        let ikm = Secret::random(ciphersuite, provider.rand())?;
        let encryption_keypair = derive_hpke_keypair(provider, ciphersuite, ikm)?;
        let key_package = Self::new_from_keys(
           provider,
            ciphersuite,
            signer,
            credential_with_key,
            encryption_keypair.public_key().clone().into(),
        )?;

        Ok(KeyPackageCreationResult {
            key_package,
            encryption_keypair,
        })
    }


    pub fn leaf_node_cgka(&self) -> &LeafNodeCGKA{
        &self.payload.leaf_node_cgka
    }

    pub fn leaf_node_tmka(&self) -> &LeafNodeTMKA{
        &self.payload.leaf_node_tmka
    }


}






// Private utils functions
impl KeyPackage{
    fn new_from_keys(
       provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        signer: &impl Signer,
        credential_with_key: &CredentialWithKey,
        public_key: HPKEPublicKey,
    ) -> Result<Self, SumacError> {

        let leaf_node_cgka = LeafNodeCGKA::new(credential_with_key.clone(), public_key.clone().into());

        // Sample a random leaf secret
        let leaf_secret = Secret::random(ciphersuite, provider.rand())?;
        
        let leaf_node_tmka = LeafNodeTMKA::new(provider.crypto(), ciphersuite, credential_with_key.credential.clone(), leaf_secret.into()).map_err(|err| SumacError::MLSError(err))?;

        let key_package_tbs = KeyPackageTbsPayload {
            ciphersuite,
            public_key,
            leaf_node_cgka,
            leaf_node_tmka
        };

        let key_package = key_package_tbs.sign(signer).map_err(|err| SumacError::SignatureError(err))?;

        Ok(key_package)
    }
}