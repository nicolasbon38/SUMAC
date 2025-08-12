use openmls::prelude::{Ciphersuite, HpkeCiphertext, OpenMlsCrypto};
use openmls_traits::OpenMlsProvider;

use crate::{crypto::types::{HPKEPrivateKey, HPKEPublicKey}, errors::SumacError};

use super::{secret::Secret, types::HPKEEncryptionKeyPair};

pub(crate) fn derive_hpke_keypair(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    secret: Secret,
) -> Result<HPKEEncryptionKeyPair, SumacError> {
    let keypair = provider
        .crypto()
        .derive_hpke_keypair(ciphersuite.hpke_config(), secret.as_slice())
        .map_err(|e| SumacError::CryptoError(e))?;

    Ok(HPKEEncryptionKeyPair::from(keypair))
}

pub(crate) fn hpke_encrypt_secret(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    secret: &Secret,
    key: &HPKEPublicKey,
) -> Result<HpkeCiphertext, SumacError> {
    provider
        .crypto()
        .hpke_seal(
            ciphersuite.hpke_config(),
            key.as_slice(),
            &[],
            &[],
            secret.as_slice(),
        )
        .map_err(|err| SumacError::CryptoError(err))
}


pub(crate) fn hpke_decrypt_secret(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    ciphertext: &HpkeCiphertext,
    key: &HPKEPrivateKey,
) -> Result<Secret, SumacError> {
    provider
        .crypto()
        .hpke_open(ciphersuite.hpke_config(), &ciphertext, key.as_vec().as_slice(), &[], &[])
        .map(|bytes| Secret::from_slice(bytes.as_slice()))
        .map_err(|err| SumacError::CryptoError(err))
}
