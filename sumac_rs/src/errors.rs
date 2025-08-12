use std::fmt;

use openmls::{error::LibraryError, prelude::SignatureError};
use openmls_traits::types::CryptoError;


#[derive(Debug)]
pub enum SumacError{
    TrueSumacError(String), // TODO: compléter au fur et à mesure
    MLSError(LibraryError),
    CryptoError(CryptoError),
    SignatureError(SignatureError),
}




impl fmt::Display for SumacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self{
            SumacError::TrueSumacError(_) => todo!(),
            SumacError::MLSError(library_error) => write!(f, "Internal OpenMLSError: {:?}", library_error),
            SumacError::CryptoError(crypto_error) => write!(f, "Internal CryptoError: {:?}", crypto_error),
            SumacError::SignatureError(signature_error) => write!(f, "Internal SignatureError: {:?}", signature_error),
        }
    }
}

impl std::error::Error for SumacError {}