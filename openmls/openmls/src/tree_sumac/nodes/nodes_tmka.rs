use std::{collections::HashSet, fmt};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
};
use tls_codec::{TlsSerialize, TlsSize};

use crate::{
    binary_tree::array_representation::ParentNodeIndex,
    error::LibraryError,
    prelude::{
        Credential, CredentialType, CredentialWithKey, LeafNodeIndex, PathSecret, Secret,
    },
    tree_sumac::{
        diff::SumacTreeDiff, nodes::{
            encryption_keys::{AeadCiphertext, SymmetricKey}, traits::{Leaf, White}, NodeReference, PlainUpdatePathNode
        }
    },
    treesync::node::parent_node::UnmergedLeaves,
};

use super::traits::{ConcreteNode, OptionNode, Parent};

//////////////////////////TMKA//////////////
///
/// Leaf
#[derive(Clone, Default)]
pub struct OptionLeafNodeTMKA {
    node: Option<LeafNodeTMKA>,
}

impl fmt::Debug for OptionLeafNodeTMKA{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.node{
            Some(content) => write!(f, "{}", content.leaf_secret().as_slice()[0])    ,
            None => write!(f, "xx"),
        }
    }
}

impl OptionNode for OptionLeafNodeTMKA {
    type Node = LeafNodeTMKA;

    fn node(&self) -> &Option<LeafNodeTMKA> {
        &self.node
    }

    fn node_mut(&mut self) -> &mut Option<LeafNodeTMKA> {
        &mut self.node
    }
}

#[derive(Clone, TlsSize, TlsSerialize)]
pub struct LeafNodeTMKA {
    payload: LeafNodeTMKAPayload,
    // signature: Signature
}


impl ConcreteNode for LeafNodeTMKA {
    type EncryptionKey = SymmetricKey;
    type DecryptionKey = SymmetricKey;
    type KeyPair = SymmetricKey;

    type EncryptedPathSecret = AeadCiphertext;

    fn encrypt_path_secret(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        plain: &PlainUpdatePathNode<Self>,
        key: &Self::EncryptionKey,
    ) -> Result<Self::EncryptedPathSecret, LibraryError> {
        key.encrypt(
            crypto,
            ciphersuite,
            plain.path_secret().clone().secret().as_slice(),
        )
    }

    fn encryption_key(&self) -> &Self::EncryptionKey {
        &self.payload.encryption_key
    }

    fn decrypt(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &Self::EncryptedPathSecret,
        key: &Self::DecryptionKey,
    ) -> Result<PathSecret, LibraryError> {
        key.decrypt(crypto, ciphersuite, ciphertext)
            .map(|vec| PathSecret::from(Secret::from_slice(vec.as_slice())))
    }
}

impl Leaf for LeafNodeTMKA {}

#[derive(Clone, TlsSize, TlsSerialize)]
struct LeafNodeTMKAPayload {
    encryption_key: SymmetricKey,
    leaf_secret: Secret,
    credential: Credential,
}

impl LeafNodeTMKA {
    pub fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        credential: Credential,
        leaf_secret: Secret,
    ) -> Result<Self, LibraryError> {
        let path_secret = PathSecret::from(leaf_secret.clone());
        let encryption_key =
            SymmetricKey::derive_from_path_secret(crypto, ciphersuite, &path_secret)?;
        let payload = LeafNodeTMKAPayload {
            encryption_key,
            leaf_secret,
            credential
        };

        let leaf_node = LeafNodeTMKA { payload };

        Ok(leaf_node)
    }

    pub fn leaf_secret(&self) -> &Secret{
        &self.payload.leaf_secret
    }

    pub fn credential(&self) -> &Credential{
        &self.payload.credential
    }
}

impl Into<OptionLeafNodeTMKA> for LeafNodeTMKA {
    fn into(self) -> OptionLeafNodeTMKA {
        OptionLeafNodeTMKA { node: Some(self) }
    }
}

impl White for LeafNodeTMKA {
    fn white(ciphersuite: Ciphersuite) -> Self {
        let payload = LeafNodeTMKAPayload {
            encryption_key: SymmetricKey::zero(ciphersuite),
            leaf_secret: Secret::zero(ciphersuite),
            credential: Credential::new(CredentialType::Basic, vec![0]),
        };
        Self { payload }
    }
}


impl LeafNodeTMKA{
    pub(crate) fn derive_regeneration_secret(&self, crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite) -> Result<Secret, CryptoError>{
        self.leaf_secret().clone().derive_secret(crypto, ciphersuite, "regen")
    }

    pub fn derive_whole_leaf_regeneration(&self, crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite) -> Result<Self, CryptoError>{
        let new_secret = self.leaf_secret().clone().derive_secret(crypto, ciphersuite, "regen")?;
        let payload = LeafNodeTMKAPayload { encryption_key: SymmetricKey::zero(ciphersuite), leaf_secret: new_secret, credential: self.payload.credential.clone() };
        Ok(Self{
            payload,
        })
    }

    pub(crate) fn absorb_regeneration_secret(&self, crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite, regeneration_secret : Secret) -> Result<Self, CryptoError>{
        let input = [self.leaf_secret().clone().as_slice(), regeneration_secret.as_slice()].concat();

        let new_leaf_secret = crypto.hkdf_expand(ciphersuite.hash_algorithm(), input.as_slice(), &[], ciphersuite.hash_length())?;
        let encryption_key = SymmetricKey::derive_from_path_secret(crypto, ciphersuite, &PathSecret::from(Secret::from_slice(new_leaf_secret.as_slice()))).expect("Derivation failed");
        let payload = LeafNodeTMKAPayload{
            encryption_key,
            leaf_secret: Secret::from_slice(new_leaf_secret.as_slice()),
            credential: self.payload.credential.clone(),
        };

        Ok(Self{
            payload
        })
    }
}

///Parent
#[derive(Clone, Default)]
pub struct OptionParentNodeTMKA {
    node: Option<ParentNodeTMKA>,
}

impl fmt::Debug for OptionParentNodeTMKA{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.node{
            Some(content) => write!(f, "{}", content.path_secret.clone().map_or(0, |secret| secret.path_secret.as_slice()[0])),
            None => write!(f, "xx")
        }
    }
}

impl OptionNode for OptionParentNodeTMKA {
    type Node = ParentNodeTMKA;

    fn node(&self) -> &Option<ParentNodeTMKA> {
        &self.node
    }

    fn node_mut(&mut self) -> &mut Option<ParentNodeTMKA> {
        &mut self.node
    }
}

impl From<ParentNodeTMKA> for OptionParentNodeTMKA{
    fn from(value: ParentNodeTMKA) -> Self {
        OptionParentNodeTMKA{
            node: Some(value)
        }
    }
}

#[derive(Clone)]
pub struct ParentNodeTMKA {
    path_secret: Option<PathSecret>,
    encryption_key: Option<SymmetricKey>,
    pub(super) unmerged_leaves: UnmergedLeaves,
}

impl ParentNodeTMKA {
    pub fn path_secret(&self) -> &Option<PathSecret>{
        &self.path_secret
    }

    pub fn new_from_path_secret(crypto : &impl OpenMlsCrypto, ciphersuite : Ciphersuite, path_secret : PathSecret, unmerged_leaves : Option<UnmergedLeaves>) -> Result<Self, LibraryError>{
        let encryption_key = SymmetricKey::derive_from_path_secret(crypto, ciphersuite, &path_secret)?;

        Ok(Self{
            path_secret: Some(path_secret),
            encryption_key : Some(encryption_key),
            unmerged_leaves: unmerged_leaves.unwrap_or(UnmergedLeaves::new()),
        })
    }
}



impl ConcreteNode for ParentNodeTMKA {
    type EncryptionKey = SymmetricKey;
    type DecryptionKey = SymmetricKey;
    type KeyPair = SymmetricKey;
    type EncryptedPathSecret = AeadCiphertext;

    fn encrypt_path_secret(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        plain: &PlainUpdatePathNode<Self>,
        key: &Self::EncryptionKey,
    ) -> Result<Self::EncryptedPathSecret, LibraryError> {
        key.encrypt(
            crypto,
            ciphersuite,
            plain.path_secret().clone().secret().as_slice(),
        )
    }

    fn encryption_key(&self) -> &Self::EncryptionKey {
        match &self.encryption_key {
            Some(key) => key,
            None => panic!("User is not allowed to see this key"),
        }
    }

    fn decrypt(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &Self::EncryptedPathSecret,
        key: &Self::DecryptionKey,
    ) -> Result<PathSecret, LibraryError> {
        key.decrypt(crypto, ciphersuite, ciphertext)
            .map(|res| PathSecret::from(Secret::from_slice(res.as_slice())))
    }
}

impl Parent for ParentNodeTMKA {
    fn unmerged_leaves(&self) -> &[LeafNodeIndex] {
        self.unmerged_leaves.list()
    }

    fn add_unmerged_leaf(&mut self, leaf_index: LeafNodeIndex) {
        self.unmerged_leaves.add(leaf_index);
    }

    fn derive_path(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path_secret: PathSecret,
        path_indices: Vec<ParentNodeIndex>,
    ) -> Result<
        (
            Vec<(ParentNodeIndex, ParentNodeTMKA)>,
            Vec<PlainUpdatePathNode<ParentNodeTMKA>>,
            Vec<SymmetricKey>,
            PathSecret
        ),
        LibraryError,
    > {
        let mut next_path_secret = path_secret;
        let mut path_secrets = Vec::with_capacity(path_indices.len());

        for _ in 0..path_indices.len() {
            let path_secret = next_path_secret;
            // Derive the next path secret.
            next_path_secret = path_secret.derive_path_secret(crypto, ciphersuite)?;
            path_secrets.push(path_secret);
        }

        type PathDerivationResults = (
            Vec<((ParentNodeIndex, ParentNodeTMKA), SymmetricKey)>,
            Vec<PlainUpdatePathNode<ParentNodeTMKA>>,
        );

        // Iterate over the path secrets and derive a key pair
        let path_secrets = path_secrets.into_iter();

        let (path_with_keys, update_path_nodes): PathDerivationResults = path_secrets
            .zip(path_indices)
            .map(|(path_secret, index)| {
                // Derive a symmetric key from the path secret.
                let symmetric_key =
                    SymmetricKey::derive_from_path_secret(crypto, ciphersuite, &path_secret)?;

                let parent_node = ParentNodeTMKA::from(path_secret.clone(), symmetric_key.clone());
                // Store the current path secret and the derived public key for
                // later encryption.
                let update_path_node = PlainUpdatePathNode {
                    public_key: symmetric_key.clone(),
                    path_secret,
                };
                Ok((((index, parent_node), symmetric_key), update_path_node))
            })
            .collect::<Result<
                Vec<(
                    ((ParentNodeIndex, ParentNodeTMKA), SymmetricKey),
                    PlainUpdatePathNode<Self>,
                )>,
                LibraryError,
            >>()?
            .into_iter()
            .unzip();

        let (path, keypairs) = path_with_keys.into_iter().unzip();

        let commit_secret = next_path_secret;
        Ok((path, update_path_nodes, keypairs , commit_secret))
    }
}

impl ParentNodeTMKA {
    pub(crate) fn from(path_secret: PathSecret, symmetric_key: SymmetricKey) -> Self {
        Self {
            path_secret: Some(path_secret),
            encryption_key: Some(symmetric_key),
            unmerged_leaves: UnmergedLeaves::new(),
        }
    }
}

impl From<SymmetricKey> for ParentNodeTMKA {
    fn from(symmetric_key: SymmetricKey) -> Self {
        Self {
            path_secret: None,
            encryption_key: Some(symmetric_key),
            unmerged_leaves: UnmergedLeaves::new(),
        }
    }
}


impl White for ParentNodeTMKA{
    fn white(_ciphersuite: Ciphersuite) -> Self {
        Self{
            path_secret: None,
            encryption_key: None,
            unmerged_leaves: UnmergedLeaves::new(),
        }
    }
}



impl ParentNodeTMKA{
    pub(crate) fn derive_regeneration_secret(&self, crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite) -> Result<Secret, CryptoError>{
        self.path_secret.clone().unwrap().secret().derive_secret(crypto, ciphersuite, "regen")
    }

    pub fn derive__whole_parent_regeneration(&self, crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite) -> Result<Self, CryptoError>{
        let secret = self.path_secret.clone().unwrap().secret().derive_secret(crypto, ciphersuite, "regen")?;
        Ok(Self{
            path_secret: Some(PathSecret::from(secret)),
            encryption_key: None,
            unmerged_leaves: self.unmerged_leaves.clone(),
        })
    }


    pub(crate) fn absorb_regeneration_secret(&self, crypto: &impl OpenMlsCrypto, ciphersuite : Ciphersuite, regeneration_secret : Secret) -> Result<Self, CryptoError>{
        let input = [self.path_secret.clone().unwrap().secret().as_slice(), regeneration_secret.as_slice()].concat();

        let new_path_secret = crypto.hkdf_expand(ciphersuite.hash_algorithm(), input.as_slice(), &[], ciphersuite.hash_length())?;
        let new_path_secret = PathSecret::from(Secret::from_slice(new_path_secret.as_slice()));
        let encryption_key = SymmetricKey::derive_from_path_secret(crypto, ciphersuite, &new_path_secret).expect("Derivation failed");
     

        Ok(Self{
            path_secret: Some(new_path_secret),
            encryption_key: Some(encryption_key),
            unmerged_leaves: self.unmerged_leaves.clone(),
        })
    }
}