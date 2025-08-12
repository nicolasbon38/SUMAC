use std::fmt::Debug;

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};

use crate::{binary_tree::array_representation::ParentNodeIndex, error::LibraryError, prelude::{LeafNodeIndex, PathSecret}, tree_sumac::nodes::PlainUpdatePathNode};


pub trait ConcreteNode : Sized{
    type EncryptionKey: Clone + Eq + PartialEq + Debug;
    type DecryptionKey;
    type KeyPair: From<(Self::EncryptionKey, Self::DecryptionKey)> + Into<(Self::EncryptionKey, Self::DecryptionKey)>;
    type EncryptedPathSecret : Clone + Debug;

    fn encrypt_path_secret(crypto: &impl OpenMlsCrypto, ciphersuite: Ciphersuite, plain: &PlainUpdatePathNode<Self>, key : &Self::EncryptionKey) -> Result<Self::EncryptedPathSecret, LibraryError>;
    fn decrypt(crypto : &impl OpenMlsCrypto, ciphersuite : Ciphersuite, ciphertext : &Self::EncryptedPathSecret,  key : &Self::DecryptionKey) -> Result<PathSecret, LibraryError>;
    fn encryption_key(&self) -> &Self::EncryptionKey;
}


pub trait OptionNode: Default{
    type Node: ConcreteNode + Clone;
    fn blank() -> Self{
        Self::default()
    }

    fn node(&self) -> &Option<Self::Node>;

    /// Return a mutable reference to the contained `Option<Node>`.
    fn node_mut(&mut self) -> &mut Option<Self::Node>;


    fn from_concrete_node(node: Self::Node) -> Self{
        let mut instance = Self::blank();
        *instance.node_mut() = Some(node);
        instance
    }

}




pub(crate) trait Leaf: ConcreteNode{}

pub trait Parent: ConcreteNode + Sized{
    fn unmerged_leaves(&self) -> &[LeafNodeIndex];

    /// Add a [`LeafNodeIndex`] to the node's list of unmerged leaves.
    fn add_unmerged_leaf(&mut self, leaf_index: LeafNodeIndex);

    //Derives a path from the given path secret.
    // Returns the resulting vector of [`ParentNode`] instances
    fn derive_path(crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite, path_secret : PathSecret, path_indices: Vec<ParentNodeIndex>) -> Result<(Vec<(ParentNodeIndex, Self)>, Vec<PlainUpdatePathNode<Self>>, Vec<Self::KeyPair>, PathSecret), LibraryError>;
}


pub trait White{
    fn white(ciphersuite: Ciphersuite) -> Self;
}