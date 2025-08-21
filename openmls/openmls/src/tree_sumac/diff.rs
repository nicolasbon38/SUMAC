use std::{collections::HashSet, fmt::Debug};

use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, types::Ciphersuite, OpenMlsProvider,
};

use crate::{
    binary_tree::{
        array_representation::{ParentNodeIndex, TreeNodeIndex, MIN_TREE_SIZE},
        MlsBinaryTreeDiff, StagedMlsBinaryTreeDiff,
    },
    error::LibraryError,
    prelude::{LeafNodeIndex, PathSecret, Secret},
    tree_sumac::{
        error::ApplyUpdatePathError, nodes::{encryption_keys::{KeyPairRef, SymmetricKey}, traits::White, PlainUpdatePathNode}, treekem::UpdatePath, LeafNodeTMKA, OptionLeafNodeTMKA, OptionParentNodeTMKA, ParentNodeTMKA
    }, treesync::node::parent_node::UnmergedLeaves,
};

use super::{
    error::{TreeSumacAddLeaf, TreeSumacError},
    nodes::{
        traits::{ConcreteNode, Leaf, OptionNode, Parent},
        NodeReference,
    },
    SumacTree,
};

/// The [`StagedTreeSyncDiff`] can be created from a [`TreeSyncDiff`], examined
/// and later merged into a [`TreeSync`] instance.
#[derive(Debug)]
// #[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub struct StagedSumacTreeDiff<L: Clone + Default + Debug, P: Clone + Default + Debug> {
    diff: StagedMlsBinaryTreeDiff<L, P>,
}

impl<L, P> StagedSumacTreeDiff<L, P>
where
    L: Clone + Debug + Default,
    P: Clone + Debug + Default,
{
    pub(super) fn into_parts(self) -> StagedMlsBinaryTreeDiff<L, P> {
        self.diff
    }
}

/// A [`TreeSyncDiff`] serves as a way to perform changes on an otherwise
/// immutable [`TreeSync`] instance. Before the changes made to a
/// [`TreeSyncDiff`] can be merged into the original [`TreeSync`] instance, it
/// has to be turned into a [`StagedTreeSyncDiff`], upon which a number of
/// checks are performed to ensure that the changes preseve the [`TreeSync`]
/// invariants. See [`TreeSync`] for the list of invariants.
pub struct SumacTreeDiff<'a, L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
{
    pub diff: MlsBinaryTreeDiff<'a, L, P>,
}

impl<'a, L, P> From<&'a SumacTree<L, P>> for SumacTreeDiff<'a, L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
{
    fn from(sumac_tree: &'a SumacTree<L, P>) -> Self {
        Self {
            diff: sumac_tree.tree.empty_diff(),
        }
    }
}

impl<L, P, K, C, DK, KP> SumacTreeDiff<'_, L, P>
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
    DK: Debug,
{
    /// Compute the position of the highest node in the tree in the filtered
    /// copath resolution of the given `sender_leaf_index` where a corresponding
    /// KP can be found.
    ///
    /// Returns the resulting position, as well as the private key of that node.
    /// Returns an error if the given `sender_leaf_index` is outside of the
    /// tree.
    pub(crate) fn decryption_key<'private_key>(
        &self,
        sender_leaf_index: LeafNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
        owned_keys: &'private_key [&KP],
        leaf_index: LeafNodeIndex,
    ) -> Result<(&'private_key DK, usize), TreeSumacError>
    where
        K: 'private_key,
    {
        // Get the copath node of the sender that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_copath_node_id = self
            .diff
            .subtree_root_copath_node(sender_leaf_index, leaf_index);

        let sender_copath_resolution = self
            .resolution(subtree_root_copath_node_id, excluded_indices)
            .into_iter()
            .map(|(_, node_ref)| match node_ref {
                NodeReference::Leaf(leaf) => leaf.encryption_key().clone(),
                NodeReference::Parent(parent) => parent.encryption_key().clone(),
            });

        if let Some((decryption_key, resolution_position)) = sender_copath_resolution
            .enumerate()
            .find_map(|(position, pk)| {
                owned_keys
                    .iter()
                    .find(|owned_keypair| {
                        let encryption_key = owned_keypair.public_key();
                        *encryption_key == pk
                    })
                    .map(|keypair| {
                        let decryption_key = keypair.private_key();
                        (decryption_key, position)
                    })
            })
        {
            // debug!("Found fitting keypair in the filtered resolution:");
            // debug!("* private key: {:x?}", keypair.private_key());
            // debug!("* public key: {:x?}", keypair.public_key());

            return Ok((decryption_key, resolution_position));
        };
        Err(TreeSumacError::NoPrivateKeyFound)
    }

    /// Filtered direct path, skips the nodes whose copath resolution is empty.
    pub fn filtered_direct_path(&self, leaf_index: LeafNodeIndex) -> Vec<ParentNodeIndex> {
        // Full direct path
        let direct_path = self.diff.direct_path(leaf_index);

        // Copath resolutions
        let copath_resolutions = self.copath_resolutions(leaf_index);

        // The two vectors should have the same length
        debug_assert_eq!(direct_path.len(), copath_resolutions.len());

        direct_path
            .into_iter()
            .zip(copath_resolutions)
            .filter_map(|(index, resolution)| {
                // Filter out the nodes whose copath resolution is empty
                if !resolution.is_empty() {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Compute the resolution of the copath of the leaf node corresponding to
    /// the given leaf index. This includes the neighbour of the given leaf. If
    /// an exclusion list is given, do not add the public keys of the leaves
    /// given in the list.
    ///
    /// Returns a vector containing the copath resolutions of the given
    /// `leaf_index` beginning with the neighbour of the leaf. Returns an error
    /// if the target leaf is outside of the tree.
    pub(crate) fn copath_resolutions(
        &self,
        leaf_index: LeafNodeIndex,
    ) -> Vec<Vec<(TreeNodeIndex, NodeReference<L::Node, P::Node>)>> {
        // If we're the only node in the tree, there's no copath.
        if self.diff.leaf_count() == MIN_TREE_SIZE {
            return vec![];
        }

        //TODO: here, check what is the point of HashSet::new() ? How is it handled in the original library ?

        // Get the copath of the given leaf index and compute the resolution of
        // each node.
        self.diff
            .copath(leaf_index)
            .into_iter()
            .map(|node_index| self.resolution(node_index, &HashSet::new()))
            .collect()
    }

    /// Compute the copath resolutions, but leave out empty resolutions.
    /// Additionally, resolutions are filtered by the given exclusion list.
    pub(super) fn filtered_copath_resolutions(
        &self,
        leaf_index: LeafNodeIndex,
        exclusion_list: &HashSet<&LeafNodeIndex>,
    ) -> Vec<Vec<(TreeNodeIndex, NodeReference<L::Node, P::Node>)>> {
        // If we're the only node in the tree, there's no copath.
        if self.diff.leaf_count() == 1 {
            return vec![];
        }

        let mut copath_resolutions = Vec::new();
        for node_index in self.diff.copath(leaf_index) {
            let resolution = self.resolution(node_index, &HashSet::new());
            if !resolution.is_empty() {
                let filtered_resolution = resolution
                    .into_iter()
                    .filter_map(|(index, node)| {
                        if let TreeNodeIndex::Leaf(leaf_index) = index {
                            if exclusion_list.contains(&leaf_index) {
                                None
                            } else {
                                Some((TreeNodeIndex::Leaf(leaf_index), node))
                            }
                        } else {
                            Some((index, node))
                        }
                    })
                    .collect();
                copath_resolutions.push(filtered_resolution);
            }
        }
        copath_resolutions
    }

    /// Helper function computing the resolution of a node with the given index.
    /// If an exclusion list is given, do not add the leaves given in the list.
    pub(super) fn resolution(
        &self,
        node_index: TreeNodeIndex,
        excluded_indices: &HashSet<&LeafNodeIndex>,
    ) -> Vec<(TreeNodeIndex, NodeReference<L::Node, P::Node>)> {
        match node_index {
            TreeNodeIndex::Leaf(leaf_index) => {
                // If the node is a leaf, check if it is in the exclusion list.
                if excluded_indices.contains(&leaf_index) {
                    vec![]
                } else {
                    // If it's not, return it as its resolution.
                    if let Some(leaf) = self.diff.leaf(leaf_index).node() {
                        vec![(TreeNodeIndex::Leaf(leaf_index), NodeReference::Leaf(leaf))]
                    } else {
                        // If it's a blank, return an empty vector.
                        vec![]
                    }
                }
            }
            TreeNodeIndex::Parent(parent_index) => {
                match self.diff.parent(parent_index).node() {
                    Some(parent) => {
                        // If it's a non-blank parent node, get the unmerged
                        // leaves, exclude them as necessary and add the node to
                        // the resulting resolution.
                        let mut resolution = vec![(
                            TreeNodeIndex::Parent(parent_index),
                            NodeReference::Parent(parent),
                        )];
                        for leaf_index in parent.unmerged_leaves() {
                            if !excluded_indices.contains(&leaf_index) {
                                let leaf = self.diff.leaf(*leaf_index);
                                // TODO #800: unmerged leaves should be checked
                                if let Some(leaf_node) = leaf.node() {
                                    resolution.push((
                                        TreeNodeIndex::Leaf(*leaf_index),
                                        NodeReference::Leaf(leaf_node),
                                    ))
                                } else {
                                    debug_assert!(false, "Unmerged leaves should not be blank.");
                                }
                            }
                        }
                        resolution
                    }
                    None => {
                        // If it is a blank parent node, continue resolving
                        // down the tree.
                        let mut resolution = Vec::new();
                        let left_child = self.diff.left_child(parent_index);
                        let right_child = self.diff.right_child(parent_index);
                        resolution.append(&mut self.resolution(left_child, excluded_indices));
                        resolution.append(&mut self.resolution(right_child, excluded_indices));
                        resolution
                    }
                }
            }
        }
    }

    /// Trims the tree by shrinking it until the last full leaf is in the
    /// right part of the tree.
    fn trim_tree(&mut self) {
        // Nothing to trim if there's only one leaf left.
        if self.leaf_count() == MIN_TREE_SIZE {
            return;
        }

        let rightmost_full_leaf = self.rightmost_full_leaf();

        // We shrink the tree until the last full leaf is the right part of the
        // tree
        while self.diff.size().leaf_is_left(rightmost_full_leaf) {
            let res = self.diff.shrink_tree();
            // We should never run into an error here, since `leaf_is_left`
            // returns false when the tree only has one leaf.
            debug_assert!(res.is_ok());
        }
    }

    /// Returns the index of the last full leaf in the tree.
    fn rightmost_full_leaf(&self) -> LeafNodeIndex {
        let mut index = LeafNodeIndex::new(0);
        for (leaf_index, leaf) in self.diff.leaves() {
            if leaf.node().as_ref().is_some() {
                index = leaf_index;
            }
        }
        index
    }

    /// Returns the number of leaves in the tree that would result from merging
    /// this diff.
    pub(crate) fn leaf_count(&self) -> u32 {
        self.diff.leaf_count()
    }

    /// Find and return the index of either the left-most blank leaf, or, if
    /// there are no blank leaves, the leaf count.
    pub(crate) fn free_leaf_index(&self) -> LeafNodeIndex {
        let mut leaf_count = 0;
        // Search for blank leaves in existing leaves
        for (leaf_index, leaf_id) in self.diff.leaves() {
            if leaf_id.node().is_none() {
                return leaf_index;
            }
            leaf_count += 1;
        }

        // Return the next free virtual blank leaf
        LeafNodeIndex::new(leaf_count)
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by
    /// extending the tree to the right to create a new leaf, inserting
    /// intermediate blanks as necessary. This also adds the leaf_index of the
    /// new leaf to the `unmerged_leaves` of the parent nodes in its direct
    /// path.
    ///
    /// Returns the LeafNodeIndex of the new leaf.
    pub fn add_leaf(&mut self, leaf_node: L) -> Result<LeafNodeIndex, TreeSumacAddLeaf> {
        // Find a free leaf and fill it with the new key package.
        let leaf_index = self.free_leaf_index();
        // If the free leaf index is within the tree, put the new leaf there,
        // otherwise extend the tree first.
        while leaf_index.u32() >= self.diff.size().leaf_count() {
            self.diff
                .grow_tree()
                .map_err(|_| TreeSumacAddLeaf::TreeFull)?;
        }
        self.diff.replace_leaf(leaf_index, leaf_node.into());

        // Add new unmerged leaves entry to all nodes in direct path. Also, wipe
        // the cached tree hash.
        for parent_index in self.diff.direct_path(leaf_index) {
            // We know that the nodes from the direct path are in the tree
            let tsn = self.diff.parent_mut(parent_index);
            if let Some(ref mut parent_node) = tsn.node_mut() {
                parent_node.add_unmerged_leaf(leaf_index);
            }
        }
        Ok(leaf_index)
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    /// After blanking the leaf and its direct path, the diff is trimmed, i.e.
    /// leaves are removed until the right-most leaf in the tree, as well as its
    /// parent are non-blank.
    ///
    /// Returns an error if the target leaf is outside of the tree.
    pub fn blank_leaf(&mut self, leaf_index: LeafNodeIndex) {
        self.diff.replace_leaf(leaf_index, L::blank());
        // This also erases any cached tree hash in the direct path.
        self.diff.set_direct_path_to_node(leaf_index, &P::blank());
        self.trim_tree();
    }

    /// Derive a new direct path for the leaf with the given index.
    ///
    /// Returns an error if the leaf is not in the tree
    fn derive_path(
        &self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        leaf_index: LeafNodeIndex,
        initial_path_secret: Option<PathSecret>, //empty for CGKA, leaf secret if TMKA
    ) -> Result<
        (
            Vec<(ParentNodeIndex, P::Node)>,
            Vec<PlainUpdatePathNode<P::Node>>,
            Vec<KP>,
            PathSecret,
        ),
        LibraryError,
    > {
        let path_secret = initial_path_secret.unwrap_or(PathSecret::from(
            Secret::random(ciphersuite, rand).map_err(LibraryError::unexpected_crypto_error)?,
        ));

        // Derive a first path secret
        let path_secret = path_secret.derive_path_secret(crypto, ciphersuite)?;

        let path_indices = self.filtered_direct_path(leaf_index);
        P::Node::derive_path(crypto, ciphersuite, path_secret, path_indices)
    }

    // Process a given update path, consisting of a vector of `ParentNode`.
    /// This function replaces the nodes in the direct path of the given
    /// `leaf_index` with the the ones in `path`.
    pub fn process_update_path(
        &mut self,
        leaf_index: LeafNodeIndex,
        path: Vec<(ParentNodeIndex, P::Node)>,
    ) -> Result<(), LibraryError> {
        // // // While probably not necessary, the spec mandates we blank the direct path nodes
        let direct_path_nodes = self.diff.direct_path(leaf_index);
        for node in direct_path_nodes {
            *self.diff.parent_mut(node) = P::blank();
        }
        // Set the node of the filtered direct path.
        for (index, node) in path.into_iter() {
            *self.diff.parent_mut(index) = P::from_concrete_node(node);
        }
        Ok(())
    }

    pub fn apply_own_update_path(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        leaf_index: LeafNodeIndex,
        new_leaf: Option<L>,
        leaf_secret: Option<PathSecret>,
    ) -> Result<(Vec<PlainUpdatePathNode<P::Node>>, Vec<KP>, PathSecret), TreeSumacAddLeaf> {
        let (path, plain_update_path, parent_keypairs, commit_secret) = self.derive_path(
            provider.rand(),
            provider.crypto(),
            ciphersuite,
            leaf_index,
            leaf_secret,
        )?;
        self.process_update_path(leaf_index, path)?;

        // We insert the fresh leaf into the tree, if it exists.
       new_leaf.map(|leaf| self.diff.replace_leaf(leaf_index, leaf.into()));

        // Prepend parent keypairs with node keypair
        let mut keypairs = vec![];
        keypairs.extend(parent_keypairs);

        Ok((plain_update_path, keypairs, commit_secret))
    }

    /// Set the given path as the direct path of the `sender_leaf_index` and
    /// replace the [`LeafNode`] in the corresponding leaf with the given one.
    ///
    /// Returns an error if the `sender_leaf_index` is outside of the tree.
    /// ValSem202: Path must be the right length
    /// TODO #804
    pub fn apply_received_update_path(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        sender_leaf_index: LeafNodeIndex,
        update_path: &UpdatePath<L::Node, P::Node>,
    ) -> Result<(), ApplyUpdatePathError> {
        let path = update_path.nodes();

        // ValSem202: Path must be the right length
        // https://validation.openmls.tech/#valn1101
        let filtered_direct_path = self.filtered_direct_path(sender_leaf_index);
        if filtered_direct_path.len() != path.len() {
            return Err(ApplyUpdatePathError::PathLengthMismatch);
        };

        let path = filtered_direct_path
            .into_iter()
            .zip(
                path.iter()
                    .map(|update_path_node| update_path_node.encryption_key.clone().into()),
            )
            .collect();

        self.process_update_path(sender_leaf_index, path)?;

        // update the leaf
        self.just_replace_leaf(L::from_concrete_node(update_path.leaf_node().clone()) , sender_leaf_index);

        Ok(())
    }

    /// This turns the diff into a staged diff. In the process, the diff
    /// computes and sets the new tree hash.
    pub fn into_staged_diff(self) -> Result<StagedSumacTreeDiff<L, P>, LibraryError> {
        Ok(StagedSumacTreeDiff {
            diff: self.diff.into(),
        })
    }

    /// Returns the position of the subtree root shared by both given indices in
    /// the direct path of `leaf_index_1`.
    ///
    /// Returns a [LibraryError] if there's an error in the tree math computation.
    pub fn subtree_root_position(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Result<usize, TreeSumacError> {
        let subtree_root_node_index = self.diff.lowest_common_ancestor(leaf_index_1, leaf_index_2);
        let leaf_index_1_direct_path = self.filtered_direct_path(leaf_index_1);

        leaf_index_1_direct_path
            .iter()
            .position(|&direct_path_node_index| direct_path_node_index == subtree_root_node_index)
            // The shared subtree root has to be in the direct path of both nodes.
            .ok_or_else(|| LibraryError::custom("index should be in the direct path").into())
    }



    /// Returns the filtered common path two leaf nodes share. If the leaves are
    /// identical, the common path is the leaf's direct path.
    pub fn filtered_common_direct_path(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Vec<ParentNodeIndex> {
        let mut x_path = self.filtered_direct_path(leaf_index_1);
        let mut y_path = self.filtered_direct_path(leaf_index_2);
        x_path.reverse();
        y_path.reverse();

        let mut common_path = vec![];

        for (x, y) in x_path.iter().zip(y_path.iter()) {
            if x == y {
                common_path.push(*x);
            } else {
                break;
            }
        }

        common_path.reverse();
        common_path
    }

    /// Updates an existing leaf node and blanks the nodes in the updated leaf's
    /// direct path.
    ///
    /// Returns an error if the target leaf is blank or outside of the tree.
    pub fn update_leaf(&mut self, leaf_node: L, leaf_index: LeafNodeIndex) {
        self.diff.replace_leaf(leaf_index, leaf_node.into());
        // This effectively wipes the tree hashes in the direct path.
        self.diff.set_direct_path_to_node(leaf_index, &P::default());
    }


    pub fn just_replace_leaf(&mut self, leaf_node : L, leaf_index: LeafNodeIndex){
        self.diff.replace_leaf(leaf_index, leaf_node.into());
    }

    pub fn just_replace_parent(&mut self, parent_node : P, parent_index: ParentNodeIndex){
        self.diff.replace_parent(parent_index, parent_node.into());
    }
}

impl<L, P> SumacTreeDiff<'_, L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
    L::Node: Leaf + White + Into<L>,
    P::Node: Parent + White + Into<P>,
{
    pub fn whiten(&mut self, ciphersuite: Ciphersuite) {
        let leaf_indices: Vec<_> = self.diff.leaves().map(|(index, _)| index).collect();
        for index_leaf in leaf_indices {
            if self.diff.leaf(index_leaf).node().is_some() {
                self.diff
                    .replace_leaf(index_leaf, L::Node::white(ciphersuite).into());
            }
        }

        // Collect parent indices next
        let parent_indices: Vec<_> = self.diff.parents().map(|(index, _)| index).collect();
        for index_parent in parent_indices {
            if self.diff.parent(index_parent).node().is_some() {
                self.diff
                    .replace_parent(index_parent, P::Node::white(ciphersuite).into());
            }
        }
    }
}


impl<'a> SumacTreeDiff<'a, OptionLeafNodeTMKA, OptionParentNodeTMKA>{
    pub fn decrypt_path_secret_from_update_path(
        &mut self,
        crypto : &impl OpenMlsCrypto,
        ciphersuite : Ciphersuite,
        encrypted_path_secrets: &Vec<Vec<u8>>,
        updated_leaf_index: &LeafNodeIndex,
        own_leaf_index : &LeafNodeIndex
    ) -> PathSecret{
        let path_position = self
            .subtree_root_position(*updated_leaf_index, *own_leaf_index).expect("ici");

        let encrypted_path_secret = encrypted_path_secrets.get(path_position).unwrap();


        // Get the copath node of the updated guy that is in our direct path, as well
        // as its position in our direct path.
        let subtree_root_copath_node_id = self
            .diff
            .subtree_root_copath_node(*updated_leaf_index, *own_leaf_index);

        let decryption_keys_candidates: Vec<SymmetricKey> = self
            .resolution(subtree_root_copath_node_id, &HashSet::new())
            .into_iter()
            .map(|(_, node_ref)| match node_ref {
                NodeReference::Leaf(leaf) => leaf.encryption_key().clone(),     //"encryption ley bit this is actually decryption keys, TODO faire une méthode spéciale"
                NodeReference::Parent(parent) => {
                    parent.encryption_key().clone()
                }
            })
            .collect();

        // In this POC, I guess the resolution is always one. Maybe even in the TMKA in the generic case. If its not, I don't know...
        assert_eq!(decryption_keys_candidates.len(), 1);

        let decryption_key = decryption_keys_candidates.get(0).unwrap();

        let path_secret = decryption_key
            .decrypt(crypto, ciphersuite, encrypted_path_secret)
            .unwrap();

        PathSecret::from(Secret::from_slice(&path_secret.as_slice()))

    }


     pub fn decrypt_first_path_secret_from_update_path_with_own_key(
        &mut self,
        crypto : &impl OpenMlsCrypto,
        ciphersuite : Ciphersuite,
        encrypted_path_secrets: &Vec<Vec<u8>>,
        own_leaf_index : LeafNodeIndex
    ) -> PathSecret{
        let encrypted_path_secret = encrypted_path_secrets.get(0).unwrap();

        // this function is lonly used in a symmetric context: so encryption key = decryption key
        let binding = self.diff.leaf(own_leaf_index).node().clone().expect("why is the leaf empty ?");
        let decryption_key = binding.encryption_key();

        let path_secret = decryption_key
            .decrypt(crypto, ciphersuite, encrypted_path_secret)
            .unwrap();

        PathSecret::from(Secret::from_slice(&path_secret.as_slice()))

    }


    /// Generate a regeneration path, by deriving the path secret of each node
    pub fn generate_regeneration_path(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        leaf_node_index: &LeafNodeIndex,
        own_leaf_node_index: Option<&LeafNodeIndex>, //For Admin trees: we don't need this
        is_including_leaf: bool,
    ) -> (Option<Secret>, Vec<(ParentNodeIndex, Secret)>) {
        let path_indices = match own_leaf_node_index {
            Some(own_leaf_index) => {
                self.filtered_common_direct_path(*leaf_node_index, *own_leaf_index)
            }
            None => self.filtered_direct_path(*leaf_node_index),
        };

        let path_regeneration = path_indices
            .into_iter()
            .map(|parent_index| {
                (
                    parent_index,
                    self.diff
                        .parent(parent_index)
                        .node().clone()
                        .expect("There should be a secret because we took the filtered direct path")
                        .derive_regeneration_secret(provider.crypto(), ciphersuite)
                        .expect("Derivation of the regeneration secret failed"),
                )
            })
            .collect();
            
            ////////////////////////////////
        let regeneration_leaf = if is_including_leaf {
            Some(
                self.diff.leaf(*leaf_node_index)
                    .node().clone()
                    .expect("There should be a leaf at this index")
                    .derive_regeneration_secret(provider.crypto(), ciphersuite)
                    .expect("Derivation of secret failed"),
            )
        } else {
            None
        };

        (regeneration_leaf, path_regeneration)
    }


    pub fn absorb_regeneration_path(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        leaf_node_index: &LeafNodeIndex,
        own_leaf_node_index: Option<&LeafNodeIndex>,
        regeneration_leaf_secret: &Option<Secret>,
        regeneration_path: &Vec<(ParentNodeIndex, Secret)>,
    ) -> Result<(Option<LeafNodeTMKA>, Vec<(ParentNodeIndex, PathSecret)>, Secret), LibraryError> {
        let path_indices = match own_leaf_node_index {
            Some(own_index) => self.filtered_common_direct_path(*own_index, *leaf_node_index),
            None => self.filtered_direct_path(*leaf_node_index),
        };
        assert_eq!(path_indices.len(), regeneration_path.len());
        
        let combined_path:Vec<(ParentNodeIndex, PathSecret)> = regeneration_path
            .iter()
            .map(|(parent_index, regeneration_secret)| {
                let parent = self.diff.parent(*parent_index).node().clone().unwrap_or(ParentNodeTMKA::new_from_path_secret(provider.crypto(), ciphersuite, PathSecret::from(Secret::zero(ciphersuite)), None).unwrap());
                 let new_parent = parent.absorb_regeneration_secret(provider.crypto(), ciphersuite, regeneration_secret.clone()).map_err(|err| LibraryError::unexpected_crypto_error(err)).unwrap();
                *self.diff.parent_mut(*parent_index).node_mut() = new_parent.clone().into();
                (*parent_index, new_parent.path_secret().clone().unwrap())
            }).collect();

        let final_secret = combined_path.last().unwrap().1.clone();
        let commit_secret = final_secret.derive_path_secret(provider.crypto(), ciphersuite)?;

        let combined_leaf = regeneration_leaf_secret.clone().map(|regeneration_secret|{
            let leaf = self.diff.leaf(*leaf_node_index).node().clone().expect("It is supposed to be a leaf here");
            leaf.absorb_regeneration_secret(provider.crypto(), ciphersuite, regeneration_secret.clone()).map_err(|err| LibraryError::unexpected_crypto_error(err))
        });

        let combined_leaf = combined_leaf.map(|r| r.map(Some)) // Result<X, E> → Result<Option<X>, E>
        .unwrap_or(Ok(None))?; // If None, return Ok(None)

        Ok((combined_leaf, combined_path, commit_secret.secret()))
    }
    
}
