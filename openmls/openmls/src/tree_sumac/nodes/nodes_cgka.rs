use openmls_traits::{crypto::OpenMlsCrypto, types::{Ciphersuite, HpkeCiphertext}};
use std::fmt::{self};

use crate::{
    binary_tree::array_representation::ParentNodeIndex, error::LibraryError, prelude::{Credential, CredentialWithKey, LeafNodeIndex, PathSecret, SignaturePublicKey}, tree_sumac::nodes::{encryption_keys::{KeyPairRef, PkeKeyPair, PkePrivateKey, PkePublicKey}, PlainUpdatePathNode}, treesync::node::parent_node::UnmergedLeaves
};
use tls_codec::{TlsSerialize, TlsSize};

use super::traits::{ConcreteNode, Leaf, OptionNode, Parent};

#[derive(Clone, Default)]
pub struct OptionLeafNodeCGKA {
    node: Option<LeafNodeCGKA>,
}

impl OptionNode for OptionLeafNodeCGKA {
    type Node = LeafNodeCGKA;

    fn node(&self) -> &Option<LeafNodeCGKA> {
        &self.node
    }

    fn node_mut(&mut self) -> &mut Option<LeafNodeCGKA> {
        &mut self.node
    }
}

impl fmt::Debug for OptionLeafNodeCGKA{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {        
        write!(f, "{:#04x}", match &self.node  {
            Some(content) => content.payload.encryption_key.as_slice()[1],
            None => 0,
        })
    }
}


//TODO: implement the signature
#[derive(Clone, Debug, TlsSize, TlsSerialize, Eq, PartialEq)]
pub struct LeafNodeCGKA {
    payload: LeafNodeCGKAPayload,
    // signature: Signature,
}


impl ConcreteNode for LeafNodeCGKA {
    type EncryptionKey = PkePublicKey;
    type DecryptionKey = PkePrivateKey;
    type KeyPair = PkeKeyPair;
    type EncryptedPathSecret = HpkeCiphertext;

    fn encrypt_path_secret(crypto: &impl OpenMlsCrypto, ciphersuite: Ciphersuite, plain: &PlainUpdatePathNode<Self>, key : &Self::EncryptionKey) -> Result<Self::EncryptedPathSecret, LibraryError> {
        key.encrypt(crypto, ciphersuite, plain.path_secret().clone().secret().as_slice())
    }
    
    fn encryption_key(&self) -> &Self::EncryptionKey {
        &self.payload.encryption_key
    }
    
    fn decrypt(crypto : &impl OpenMlsCrypto, ciphersuite : Ciphersuite, ciphertext : &Self::EncryptedPathSecret,  key : &Self::DecryptionKey) -> Result<PathSecret, LibraryError> {
        key.decrypt(crypto, ciphersuite, ciphertext)
    }

}

impl Leaf for LeafNodeCGKA{}

impl LeafNodeCGKA {
    pub fn new(
        // provider: &impl OpenMlsProvider,
        // ciphersuite: Ciphersuite,
        // signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        encryption_key: PkePublicKey,
    ) -> Self {
        let payload = LeafNodeCGKAPayload {
            encryption_key: encryption_key,
            signature_key: credential_with_key.signature_key,
            credential: credential_with_key.credential,
        };

        let leaf_node = LeafNodeCGKA { payload };

        leaf_node
    }

    pub fn credential(&self) -> &Credential{
        &self.payload.credential
    }
}



impl Into<OptionLeafNodeCGKA> for LeafNodeCGKA{
    fn into(self) -> OptionLeafNodeCGKA {
        OptionLeafNodeCGKA { node: Some(self) }
    }
}


#[derive(Clone, Debug, TlsSize, TlsSerialize, Eq, PartialEq)]
struct LeafNodeCGKAPayload {
    encryption_key: PkePublicKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
}

///Parent
#[derive(Clone, Default)]
pub struct OptionParentNodeCGKA {
    node: Option<ParentNodeCGKA>,
}

impl OptionNode for OptionParentNodeCGKA {
    type Node = ParentNodeCGKA;

    fn node(&self) -> &Option<ParentNodeCGKA> {
        &self.node
    }

    fn node_mut(&mut self) -> &mut Option<ParentNodeCGKA> {
        &mut self.node
    }
}


impl fmt::Debug for OptionParentNodeCGKA{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {        
        write!(f, "{:#04x}", match &self.node  {
            Some(content) => content.encryption_key.as_slice()[1],
            None => 0,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentNodeCGKA {
    pub encryption_key: PkePublicKey,
    pub unmerged_leaves: UnmergedLeaves,
}

impl ConcreteNode for ParentNodeCGKA {
    type EncryptionKey = PkePublicKey;
    type DecryptionKey = PkePrivateKey;
    type KeyPair = PkeKeyPair;
    type EncryptedPathSecret = HpkeCiphertext;

    fn encrypt_path_secret(crypto: &impl OpenMlsCrypto, ciphersuite: Ciphersuite, plain: &PlainUpdatePathNode<Self>, key : &Self::EncryptionKey) -> Result<Self::EncryptedPathSecret, LibraryError> {
        key.encrypt(crypto, ciphersuite, plain.path_secret().clone().secret().as_slice())
    }

    fn encryption_key(&self) -> &Self::EncryptionKey {
        &self.encryption_key
    }
    
    fn decrypt(crypto : &impl OpenMlsCrypto, ciphersuite : Ciphersuite, ciphertext : &Self::EncryptedPathSecret,  key : &Self::DecryptionKey) -> Result<PathSecret, LibraryError> {
        LeafNodeCGKA::decrypt(crypto, ciphersuite, ciphertext, key)
    }
    
}

impl Parent for ParentNodeCGKA {
    fn unmerged_leaves(&self) -> &[LeafNodeIndex] {
        self.unmerged_leaves.list()
    }

    fn add_unmerged_leaf(&mut self, leaf_index: LeafNodeIndex) {
        self.unmerged_leaves.add(leaf_index);
    }


    fn derive_path(
        crypto: &impl OpenMlsCrypto,
        ciphersuite : Ciphersuite,
        path_secret : PathSecret,
        path_indices: Vec<ParentNodeIndex>
    ) -> Result<(Vec<(ParentNodeIndex, Self)>, Vec<PlainUpdatePathNode<Self>>, Vec<Self::KeyPair>, PathSecret), LibraryError> {  
        let mut next_path_secret = path_secret;
        let mut path_secrets = Vec::with_capacity(path_indices.len());

        for _ in 0..path_indices.len() {
            let path_secret = next_path_secret;
            // Derive the next path secret.
            next_path_secret = path_secret.derive_path_secret(crypto, ciphersuite)?;
            path_secrets.push(path_secret);
        }

        type PathDerivationResults = (
            Vec<((ParentNodeIndex, ParentNodeCGKA), PkeKeyPair)>,
            Vec<PlainUpdatePathNode<ParentNodeCGKA>>,
        );

        // Iterate over the path secrets and derive a key pair
        let path_secrets = path_secrets.into_iter();

        let (path_with_keypairs, update_path_nodes): PathDerivationResults = path_secrets
        .zip(path_indices)
        .map(|(path_secret, index)| {
            // Derive a key pair from the path secret. 
            let keypair = PkeKeyPair::derive_from_path_secret(crypto, ciphersuite, &path_secret)?;
            
            let parent_node = ParentNodeCGKA::from(keypair.public_key().clone());
            // Store the current path secret and the derived public key for
            // later encryption.
            let update_path_node = PlainUpdatePathNode {
                public_key : keypair.public_key().clone(),
                path_secret,
            };
            Ok((((index, parent_node), keypair), update_path_node))
        })
        .collect::<Result<
            Vec<(
                ((ParentNodeIndex, ParentNodeCGKA), PkeKeyPair),
                PlainUpdatePathNode<Self>,
            )>,
            LibraryError,
        >>()?
        .into_iter()
        .unzip();


        let (path, keypairs) = path_with_keypairs.into_iter().unzip();

        let commit_secret = next_path_secret;
        Ok((path, update_path_nodes, keypairs,  commit_secret))
    }
}



impl From<PkePublicKey> for ParentNodeCGKA{
    fn from(value: PkePublicKey) -> Self {
        Self{
            encryption_key: value,
            unmerged_leaves: UnmergedLeaves::new(),
        }
    }
}