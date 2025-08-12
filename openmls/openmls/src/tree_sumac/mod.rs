use std::{fmt::Debug, os::unix::process::parent_id};

use diff::{StagedSumacTreeDiff, SumacTreeDiff};
use either::Either;
use nodes::traits::{Leaf, OptionNode, Parent};
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};

use crate::{
    binary_tree::{
        array_representation::{tree::TreeNode, ParentNodeIndex},
        MlsBinaryTree,
    },
    error::LibraryError,
    prelude::{LeafNodeIndex, ParentNode, PathSecret, Secret}, tree_sumac::nodes::encryption_keys::PkeKeyPair,
};

pub mod nodes;


pub(crate) mod diff;
pub(crate) mod error;
pub mod treekem;
pub use error::TreeSumacError;

// Some public re-exports
pub use nodes::nodes_cgka::{
    LeafNodeCGKA, OptionLeafNodeCGKA, OptionParentNodeCGKA, ParentNodeCGKA,
};
pub use nodes::nodes_tmka::{
    LeafNodeTMKA, OptionLeafNodeTMKA, OptionParentNodeTMKA, ParentNodeTMKA,
};

#[derive(Clone)]
pub struct SumacTree<
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
> {
    tree: MlsBinaryTree<L, P>,
}

impl<L, P> SumacTree<L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
{
    pub fn tree(&self) -> &MlsBinaryTree<L, P> {
        &self.tree
    }
}

impl<L, P> SumacTree<L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode ,
    L::Node: Leaf,
    P::Node: Parent,
{
    pub fn print_debug(&self, message: &str) {
        println!("{}", message);

        let count_parents = self.tree().parent_count();
        let depth = (count_parents + 1).ilog2();

        let mut sort_by_depth: Vec<Vec<P>> = vec![];

        for i_depth in 0..depth {
            sort_by_depth.push(vec![]);
            let mut i = (1 << i_depth) - 1;
            while i < count_parents {
                let node = self.tree().parent_by_index(ParentNodeIndex::new(i));
                sort_by_depth[i_depth as usize].push(node.clone());
                i += 1 << (i_depth + 1);
            }
        }

        let max_width = sort_by_depth.iter().map(|row| row.len()).max().unwrap_or(0);
        let leaf_width = self.tree().leaves().count();
        let total_width = max_width.max(leaf_width) * 5; // Each value takes 4 characters + 1 space

        for (depth, floor) in sort_by_depth.iter().rev().enumerate() {
            let padding = (total_width - floor.len() * 3) / 2;
            print!("{:width$}", "", width = padding);
            print!("Depth {}: ", depth);
            for node in floor {
                print!("{node:?} ");
            }
            println!();
        }

        print!("  Leaves: ");
        let padding = (total_width - leaf_width * 5) / 2;
        print!("{:width$}", "", width = padding);
        self.tree().leaves().for_each(|(_, leaf)| {
            print!("{leaf:?} ");
        });
        println!();

    }

    // TODO: prévoir une initialisation meilleure que ça
    /// Create a new tree with a default leaf.
    ///
    pub fn new(leaf_node: L) -> Result<Self, LibraryError> {
        if leaf_node.node().is_none() {
            return Err(LibraryError::custom(
                "The leaf given at the creation of the node is empty",
            ));
        }
        let nodes = vec![TreeNode::Leaf(leaf_node)];
        let tree = MlsBinaryTree::new(nodes)
            .map_err(|_| LibraryError::custom("Unexpected error creating the binary tree."))?;
        let sumac_tree = Self { tree };

        Ok(sumac_tree)
    }

    /// Merge the given diff into this `SumacTree` instance.
    pub fn merge_diff(&mut self, tree_sync_diff: StagedSumacTreeDiff<L, P>) {
        let diff = tree_sync_diff.into_parts();
        self.tree.merge_diff(diff);
    }

    /// Create an empty diff based on this [`TreeSync`] instance all operations
    /// are created based on an initial, empty [`TreeSyncDiff`].
    pub fn empty_diff(&self) -> SumacTreeDiff<L, P> {
        self.into()
    }

    /// Derives [`EncryptionKeyPair`]s for the nodes in the shared direct path
    /// of the leaves with index `leaf_index` and `sender_index`.  This function
    /// also checks that the derived public keys match the existing public keys.
    pub fn derive_path_secrets(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path_secret: &[u8],
        sender_index: LeafNodeIndex,
        leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<PkeKeyPair>, PathSecret), TreeSumacError> {
        // For compatibility reasins, we reconvert it
        let mut path_secret = PathSecret::from(Secret::from_slice(path_secret));

        // We assume both nodes are in the tree, since the sender_index must be in the tree
        // Skip the nodes in the subtree path for which we are an unmerged leaf.
        let subtree_path = self.tree.subtree_path(leaf_index, sender_index);
        let mut keypairs = Vec::new();
        for parent_index in subtree_path {
            // We know the node is in the tree, since it is in the subtree path
            let tsn = self.tree.parent_by_index(parent_index);
            // We only care about non-blank nodes.
            if let Some(ref parent_node) = tsn.node() {
                // If our own leaf index is not in the list of unmerged leaves
                // then we should have the secret for this node.
                if !parent_node.unmerged_leaves().contains(&leaf_index) {
                    let keypair =
                        PkeKeyPair::derive_from_path_secret(crypto, ciphersuite, &path_secret)?;
                    // The derived public key should match the one in the node.
                    // If not, the tree is corrupt. # TODO: for now, it is impossible to do this test because of generics shenanigans. Maybe compare the underlying slices ?
                    // if parent_node.encryption_key() != keypair.public_key() {
                    //     return Err(DerivePathError::PublicKeyMismatch);
                    // } else {
                    // If everything is ok, set the private key and derive
                    // the next path secret.
                    keypairs.push(keypair);
                    path_secret = path_secret.derive_path_secret(crypto, ciphersuite)?;
                    // }
                };
                // If the leaf is blank or our index is in the list of unmerged
                // leaves, go to the next node.
            }
        }
        Ok((keypairs, path_secret))
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex` or `None` if the
    /// leaf is blank.
    pub fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&L::Node> {
        match self.tree.leaf(leaf_index).node() {
            Some(inner_node) => Some(inner_node),
            None => None,
        }
    }

    pub fn leaves(&self) -> impl Iterator<Item = (LeafNodeIndex, &L)> {
        self.tree.leaves()
    }


    /// A helper function that generates a [`TreeSumac`] instance from the given
    /// slice of nodes. 
    pub fn from_ratchet_tree(
        ratchet_tree: RatchetTree<L::Node, P::Node>,
    ) -> Self {
        // TODO #800: Unmerged leaves should be checked
        let mut ts_nodes : Vec<TreeNode<L, P>>  =
            Vec::with_capacity(ratchet_tree.0.len());

        // Set the leaf indices in all the leaves and convert the node types.
        for (node_index, node_option) in ratchet_tree.0.into_iter().enumerate() {
            let ts_node_option = match node_option {
                Some(node) => {
                    match node{
                        Either::Left(leaf) => TreeNode::<L, P>::Leaf(L::from_concrete_node(leaf)),
                        Either::Right(parent) => TreeNode::<L, P>::Parent(P::from_concrete_node(parent)),
                    }
                }
                None => {
                    if node_index % 2 == 0 {
                        TreeNode::<L, P>::Leaf(L::blank())
                    } else {
                        TreeNode::<L, P>::Parent(P::blank())
                    }
                }
            };
            ts_nodes.push(ts_node_option);
        }

        let tree = MlsBinaryTree::<L, P>::new(ts_nodes).expect("Failed to convert the ratchet tree");
        
        
        let mut sumac_tree = Self {
            tree,
        };

        sumac_tree
    }
}


///// Ratchet Tree for exports + generation of groups on the fly //////

pub type NodeVariant<L, P> = Either<L, P>;

#[derive(PartialEq, Eq)]
pub struct RatchetTree<L: Leaf, P: Parent>(
    Vec<Option<NodeVariant<L, P>>>,
);

impl<L, P> RatchetTree<L, P>
where
    L: Leaf + Clone ,
    P: Parent + Clone ,
{

    pub fn new(nodes: Vec<Option<NodeVariant<L, P>>>) -> Self {
        Self(nodes)
    }

    
    /// Create a [`RatchetTree`] from a vector of nodes stripping all trailing blank nodes.
    ///
    /// Note: The caller must ensure to call this with a vector that is *not* empty after removing all trailing blank nodes.
    fn trimmed(mut nodes: Vec<Option<NodeVariant<L, P>>>) -> Self {
        // Remove all trailing blank nodes.
        match nodes.iter().enumerate().rfind(|(_, node)| node.is_some()) {
            Some((rightmost_nonempty_position, _)) => {
                // We need to add 1 to `rightmost_nonempty_position` to keep the rightmost node.
                nodes.resize(rightmost_nonempty_position + 1, None);
            }
            None => {
                // If there is no rightmost non-blank node, the vector consist of blank nodes only.
                nodes.clear();
            }
        }

        debug_assert!(!nodes.is_empty(), "Caller should have ensured that `RatchetTree::trimmed` is not called with a vector that is empty after removing all trailing blank nodes.");
        Self(nodes)
    }
}

impl<L, P> SumacTree<L, P>
where
    L: Clone + Debug + Default + OptionNode,
    P: Clone + Debug + Default + OptionNode,
    L::Node: Leaf ,
    P::Node: Parent ,
{
    /// array-representation of the underlying binary tree.
    pub fn export_ratchet_tree(&self) -> RatchetTree<L::Node, P::Node> {
        let mut nodes = Vec::new();

        // Determine the index of the rightmost full leaf.
        let max_length = self.rightmost_full_leaf();

        // We take all the leaves including the rightmost full leaf, blank
        // leaves beyond that are trimmed.
        let mut leaves = self
            .tree
            .leaves()
            .map(|(_, leaf)| leaf)
            .take(max_length.usize() + 1);

        // Get the first leaf.
        if let Some(leaf) = leaves.next() {
            nodes.push(
                leaf.node()
                    .clone()
                    .map(|inner_leaf| NodeVariant::Left(inner_leaf)),
            );
        } else {
            // The tree was empty.
            return RatchetTree::trimmed(vec![]);
        }

        // Blank parent node used for padding
        let default_parent = P::default();

        // Get the parents.
        let parents = self
            .tree
            .parents()
            // Drop the index
            .map(|(_, parent)| parent)
            // Take the parents up to the max length
            .take(max_length.usize())
            // Pad the parents with blank nodes if needed
            .chain(
                (self.tree.parents().count()..self.tree.leaves().count() - 1)
                    .map(|_| &default_parent),
            );

        // Interleave the leaves and parents.
        for (leaf, parent) in leaves.zip(parents) {
            nodes.push(
                parent
                    .node()
                    .clone()
                    .map(|inner_parent| NodeVariant::Right(inner_parent)),
            );
            nodes.push(
                leaf.node()
                    .clone()
                    .map(|inner_leaf| NodeVariant::Left(inner_leaf)),
            );
        }

        RatchetTree::trimmed(nodes)
    }

    /// Returns the index of the last full leaf in the tree.
    fn rightmost_full_leaf(&self) -> LeafNodeIndex {
        let mut index = LeafNodeIndex::new(0);
        for (leaf_index, leaf) in self.tree.leaves() {
            if leaf.node().as_ref().is_some() {
                index = leaf_index;
            }
        }
        index
    }
}


impl<L: Leaf, P: Parent> RatchetTree<L, P> {
    pub fn iter(&self) -> impl Iterator<Item = &Option<NodeVariant<L, P>>> {
        self.0.iter()
    }
}
