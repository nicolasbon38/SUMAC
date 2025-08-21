//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.
use std::{collections::HashSet, fmt::Debug};

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};

use crate::{
    error::LibraryError,
    prelude::{LeafNodeIndex, PathSecret},
    tree_sumac::{
        nodes::{
            encryption_keys::KeyPairRef,
            traits::{ConcreteNode, Leaf, Parent},
            NodeReference, PlainUpdatePathNode,
        },
    },
};

use super::{diff::SumacTreeDiff, nodes::traits::OptionNode};

impl<L, P, K, DK, C, KP> SumacTreeDiff<'_, L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
    L::Node: Leaf,
    P::Node: Parent,
    L::Node:
        ConcreteNode<EncryptionKey = K, DecryptionKey = DK, KeyPair = KP, EncryptedPathSecret = C>,
    P::Node:
        ConcreteNode<EncryptionKey = K, DecryptionKey = DK, KeyPair = KP, EncryptedPathSecret = C>,
    KP: Into<(K, DK)> + KeyPairRef<K, DK> + Clone,
    K: Clone + Eq + PartialEq + Into<P::Node> + Debug,
    DK:Debug
{
    /// Encrypt the given `path` to the nodes in the copath resolution of the
    /// owner of this [`TreeSyncDiff`]. The `group_context` is used in the
    /// encryption of the nodes, while the `exclusion_list` is used to filter
    /// target leaves from the encryption targets. The given [`LeafNode`] is
    /// included in the resulting [`UpdatePath`].
    ///
    /// Returns the encrypted path (i.e. an [`UpdatePath`] instance).
    pub fn encrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path: &[PlainUpdatePathNode<P::Node>],
        exclusion_list: &HashSet<&LeafNodeIndex>,
        own_leaf_index: LeafNodeIndex,
    ) -> Result<Vec<UpdatePathNode<P::Node>>, LibraryError> {
        // Copath resolutions with the corresponding public keys.
        let copath_resolutions = self
            .filtered_copath_resolutions(own_leaf_index, exclusion_list)
            .into_iter()
            .map(|resolution| {
                resolution
                    .into_iter()
                    .map(|pair| {
                        let (_, node_ref): (_, NodeReference<L::Node, P::Node>) = pair;
                        match node_ref {
                            NodeReference::Leaf(leaf) => {
                                (leaf.encryption_key()).clone()
                            }
                            NodeReference::Parent(parent) => {
                                (parent.encryption_key()).clone()
                            }
                        }
                    })
                    .collect::<Vec<K>>()
            })
            .collect::<Vec<Vec<K>>>();

        // There should be as many copath resolutions.
        debug_assert_eq!(copath_resolutions.len(), path.len());

        // Encrypt the secrets
        // #[cfg(not(target_arch = "wasm32"))]
        // let resolved_path = path.par_iter().zip(copath_resolutions.par_iter());
        // #[cfg(target_arch = "wasm32")]
        let resolved_path = path.iter().zip(copath_resolutions.iter());

        resolved_path
            .map(|(node, resolution)| {node.encrypt(crypto, ciphersuite, resolution)})
            .collect::<Result<Vec<UpdatePathNode<P::Node>>, LibraryError>>()
    }

    /// Decrypt an [`UpdatePath`] originating from the given
    /// `sender_leaf_index`. The `group_context` is used in the decryption
    /// process and the `exclusion_list` is used to determine the position of
    /// the ciphertext in the `UpdatePath` that we can decrypt.
    ///
    /// Returns a vector containing the decrypted [`ParentNode`] instances, as
    /// well as the [`CommitSecret`] resulting from their derivation. Returns an
    /// error if the `sender_leaf_index` is outside of the tree.
    ///
    /// ValSem203: Path secrets must decrypt correctly
    /// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
    /// TODO #804
    pub fn decrypt_path(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        params: DecryptPathParams<P::Node>,
        owned_keys: &[&KP],
        own_leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<KP>, PathSecret), LibraryError> {
        let path_position = self
            .subtree_root_position(params.sender_leaf_index, own_leaf_index)
            .map_err(|_| LibraryError::custom("Expected own leaf to be in the tree"))?;

        let update_path_node = params
            .update_path
            .get(path_position)
            // We know the update path has the right length through validation, therefore there must be an element at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path 1"))?;

        let (decryption_key, resolution_position) = self
            .decryption_key(
                params.sender_leaf_index,
                params.exclusion_list,
                owned_keys,
                own_leaf_index,
            )
            // TODO #804
            .map_err(|_| LibraryError::custom("Expected sender to be in the tree"))?;

        let path_secret =
            update_path_node.decrypt(crypto, ciphersuite, decryption_key, resolution_position)?;

        let common_path =
            self.filtered_common_direct_path(own_leaf_index, params.sender_leaf_index);
        let (_, _plain_update_path, keypairs, commit_secret) =
            P::Node::derive_path(crypto, ciphersuite, path_secret, common_path)?;

        Ok((keypairs, commit_secret))
    }
}

pub struct DecryptPathParams<'a, N: ConcreteNode> {
    pub update_path: &'a [UpdatePathNode<N>],
    pub sender_leaf_index: LeafNodeIndex,
    pub exclusion_list: &'a HashSet<&'a LeafNodeIndex>,
}

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<V>;
/// } UpdatePathNode;
/// ```
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    // Serialize,
    // Deserialize,
    // TlsDeserialize,
    // TlsDeserializeBytes,
    // TlsSerialize,
    // TlsSize,
)]
pub struct UpdatePathNode<N: ConcreteNode> {
    pub encryption_key: N::EncryptionKey,
    pub(super) encrypted_path_secrets: Vec<N::EncryptedPathSecret>,
}

impl<N> UpdatePathNode<N>
where
    N: ConcreteNode,
{
    /// Return the `encrypted_path_secrets`.
    pub fn encrypted_path_secrets(&self, ciphertext_index: usize) -> Option<&N::EncryptedPathSecret> {
        self.encrypted_path_secrets.get(ciphertext_index)
    }

    fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key: &N::DecryptionKey,
        index: usize,
    ) -> Result<PathSecret, LibraryError> {
        let ciphertext = self
            .encrypted_path_secrets(index)
            // We know the update path has the right length through validation, therefore there must be a ciphertext at this position
            // TODO #804
            .ok_or_else(|| LibraryError::custom("Expected to find ciphertext in update path 2"))?;
        N::decrypt(crypto, ciphersuite, ciphertext, key)
    }
}

//#[derive(/* , Serialize, Deserialize, TlsSerialize, TlsSize*/)]
#[derive(Clone, Debug)]
pub struct UpdatePath<LeafNode: ConcreteNode, ParentNode: ConcreteNode> {
    leaf_node: LeafNode,
    nodes: Vec<UpdatePathNode<ParentNode>>,
}

impl<L, P> UpdatePath<L, P>
where
    L: ConcreteNode,
    P: ConcreteNode,
{
    /// Generate a new update path.
    pub fn new(leaf_node: L, nodes: Vec<UpdatePathNode<P>>) -> Self {
        Self { leaf_node, nodes }
    }

    /// Return the `leaf_node` of this [`UpdatePath`].
    pub fn leaf_node(&self) -> &L {
        &self.leaf_node
    }

    /// Return the `nodes` of this [`UpdatePath`].
    pub fn nodes(&self) -> &[UpdatePathNode<P>] {
        &self.nodes
    }
}
