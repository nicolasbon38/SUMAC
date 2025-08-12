use openmls::{prelude::{BasicCredential, Ciphersuite, CredentialWithKey}, tree_sumac::nodes::encryption_keys::KeyPairRef};
use openmls_traits::{OpenMlsProvider};

use openmls_basic_credential::SignatureKeyPair;


use crate::{crypto::types::{HPKEEncryptionKeyPair, HPKEPrivateKey}, errors::SumacError, key_package::{KeyPackage, KeyPackageCreationResult}};

#[derive(Clone)]
pub struct User {
    credential: BasicCredential,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    encryption_keypair: Option<HPKEEncryptionKeyPair>,
    key_package: Option<KeyPackage>,
}

impl User {
    pub fn credential(&self) -> &BasicCredential{
        &self.credential
    }


    pub fn signer(&self) -> &SignatureKeyPair{
        &self.signer
    }

    pub fn identity(&self) -> String {
        String::from_utf8(self.credential().identity().to_vec()).unwrap()
    }


    pub fn credential_with_key(&self) -> &CredentialWithKey {
        &self.credential_with_key
    }


    pub fn encryption_keypair(&self) -> Result<HPKEEncryptionKeyPair, SumacError> {
        self.encryption_keypair
            .clone()
            .ok_or(SumacError::TrueSumacError("KeyPackage has not been built yet".to_owned()))
    }

    pub fn key_package(&self) -> Result<KeyPackage, SumacError> {
        self.key_package
            .clone()
            .ok_or(SumacError::TrueSumacError("KeyPackage has not been built yet".to_owned()))
    }

    fn private_key_hpke(&self) -> Result<HPKEPrivateKey, SumacError>{
       self.encryption_keypair().map(|pair| pair.private_key().clone())
    }

    pub fn generate_key_package_bundle(
        &mut self,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
    ) -> Result<(), SumacError>{
        // Also initialize the private key for HPKE
        let KeyPackageCreationResult{
            key_package,
            encryption_keypair
        } =  KeyPackage::create(provider, ciphersuite, &self.signer, &self.credential_with_key)?;
        self.key_package = Some(key_package);
        self.encryption_keypair = Some(encryption_keypair);
        Ok(())
    }


    pub fn initialize_user(name: String, ciphersuite: Ciphersuite) -> Self {
        let credential = BasicCredential::new(name.into());
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: credential.clone().into(),
            signature_key: signer.to_public_vec().into(),
        };

        Self {
            credential: credential.into(),
            signer,
            credential_with_key,
            encryption_keypair: None,
            key_package: None,
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{setup_provider, CIPHERSUITE};

    #[test]
    fn test_creation_user() {
        let mut user = User::initialize_user("Alice".to_owned(), Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256);
        user.generate_key_package_bundle(CIPHERSUITE, &setup_provider()).unwrap();
    }
}