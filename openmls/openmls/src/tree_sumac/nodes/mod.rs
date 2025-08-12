use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use traits::{Leaf, Parent};

use crate::{error::LibraryError, prelude::PathSecret, tree_sumac::{nodes::traits::ConcreteNode, treekem::UpdatePathNode}};

pub mod encryption_keys;
pub mod traits;
pub(crate) mod nodes_tmka;
pub(crate) mod nodes_cgka;




/// Container enum with reference to a node in a tree.
pub(crate) enum NodeReference<'a, L : Leaf, P: Parent> {
    Leaf(&'a L),
    Parent(&'a P),
}




#[derive(Debug)]
pub struct PlainUpdatePathNode<N: ConcreteNode> {
    public_key : N::EncryptionKey,
    path_secret: PathSecret,
}


impl<N> PlainUpdatePathNode<N> where N : ConcreteNode {
    /// Encrypt this node and return the resulting [`UpdatePathNode`].
    pub fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        public_keys: &[N::EncryptionKey],
    ) -> Result<UpdatePathNode<N>, LibraryError> {
        #[cfg(target_arch = "wasm32")]
        let public_keys = public_keys.iter();
        #[cfg(not(target_arch = "wasm32"))]
        let public_keys = public_keys.iter();

        public_keys
            .map(|pk| {
                N::encrypt_path_secret(crypto, ciphersuite, self, pk)
            })
            .collect::<Result<Vec<N::EncryptedPathSecret>, LibraryError>>()
            .map(|encrypted_path_secrets| UpdatePathNode {
                encryption_key: self.public_key.clone(),
                encrypted_path_secrets,
            })
    }

    /// Return a reference to the `path_secret` of this node.
    pub fn path_secret(&self) -> &PathSecret {
        &self.path_secret
    }
    
}