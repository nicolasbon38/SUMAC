use std::collections::HashSet;

use openmls::prelude::{ParentNodeIndex, Secret as MlsSecret};
use openmls::tree_sumac::nodes::traits::OptionNode;
use openmls::tree_sumac::OptionLeafNodeTMKA;
use openmls::{
    error::LibraryError,
    prelude::{Ciphersuite, LeafNodeIndex, PathSecret},
    tree_sumac::{
        nodes::{
            encryption_keys::{KeyPairRef, SymmetricKey},
            traits::{Parent, White},
        },
        treekem::DecryptPathParams,
        LeafNodeTMKA, ParentNodeTMKA,
    },
};
use openmls_traits::OpenMlsProvider;

use crate::crypto::secret::Secret;
use crate::{
    crypto::hpke::hpke_decrypt_secret,
    errors::SumacError,
    tmka::{CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    user::User,
    Operation,
};

#[derive(Clone)]
pub struct TmkaSlaveGroup {
    pub tree: TreeTMKA,
    pub own_leaf_index: LeafNodeIndex,
    pub user: User,
    pub commit_secret : Secret
}

impl TmkaSlaveGroup {
    pub fn print_debug(&self, message: &str) {
        self.tree.print_debug(message);
    }

    pub fn process(
        &mut self,
        commit: &CommitTMKABroadcast,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(), SumacError> {
        let mut diff = self.tree.empty_diff();

        let CommitTMKABroadcast {
            encrypted_path_secrets,
            updated_leaf_index,
            operation,
        } = commit;

        match operation {
            Operation::Add(_) => {
                let white_leaf = LeafNodeTMKA::white(ciphersuite);
                let new_index = diff
                    .add_leaf(white_leaf.into())
                    .expect("Failed to add the new node while processing the broadcast");
                assert_eq!(new_index, *updated_leaf_index);
            }
            Operation::Remove(_) => {
               // nothing to do !
            }
            Operation::Update(_) => {
                // nothing to do!
            },
        }

        let path_secret = diff.decrypt_path_secret_from_update_path(provider.crypto(), ciphersuite, encrypted_path_secrets, updated_leaf_index, &self.own_leaf_index);

        let path_indices =
            diff.filtered_common_direct_path(self.own_leaf_index, *updated_leaf_index);

        let (path, _, _, commit_secret) = ParentNodeTMKA::derive_path(
            provider.crypto(),
            ciphersuite,
            path_secret,
            path_indices,
        )
        .unwrap();

        self.commit_secret = commit_secret.secret().into();

        diff.process_update_path(*updated_leaf_index, path).map_err(|err| SumacError::MLSError(err))?;

        match operation{
            Operation::Remove(user) => diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), *updated_leaf_index),
            _ =>{}
        }

        self.tree
            .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
        Ok(())
    }

    pub fn process_self_update(
        &mut self,
        commit: CommitTMKAUnicast,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(), SumacError> {
        let CommitTMKAUnicast {
            own_leaf_node_index,
            encrypted_leaf_secret,
            public_tree: _,
        } = commit;

        assert_eq!(own_leaf_node_index, self.own_leaf_index);

        // Start by decrypting the secret
        let leaf_secret = hpke_decrypt_secret(
            provider,
            ciphersuite,
            &encrypted_leaf_secret,
            self.user.encryption_keypair()?.private_key(),
        )?;

        let new_leaf_node = LeafNodeTMKA::new(
            provider.crypto(),
            ciphersuite,
            self.user.credential_with_key().credential.clone(),
            leaf_secret.clone().into(),
        )
        .map_err(|err| SumacError::MLSError(err))?;


        let mut diff = self.tree.empty_diff();
   
        diff.just_replace_leaf(new_leaf_node.clone().into(), self.own_leaf_index);
        
        let path_indices = diff.filtered_direct_path(own_leaf_node_index);

        let path_secret = PathSecret::from(MlsSecret::from(leaf_secret.into())).derive_path_secret(provider.crypto(), ciphersuite).unwrap();

        let (path, _, _, commit_secret) =
            ParentNodeTMKA::derive_path(provider.crypto(), ciphersuite, path_secret, path_indices)
                .map_err(|err| SumacError::MLSError(err))?;

        diff.process_update_path(own_leaf_node_index, path)
            .expect("Failed to update path");

        self.tree.merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
        self.commit_secret = commit_secret.secret().clone().into();

        Ok(())
    }

    pub fn process_welcome(
        commit: CommitTMKAUnicast,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        user: &User,
    ) -> Result<Self, SumacError> {
        let CommitTMKAUnicast {
            own_leaf_node_index,
            encrypted_leaf_secret,
            mut public_tree,
        } = commit;

        // Start by decrypting the secret
        let leaf_secret = hpke_decrypt_secret(
            provider,
            ciphersuite,
            &encrypted_leaf_secret,
            user.encryption_keypair()?.private_key(),
        )?;

        let new_leaf_node = LeafNodeTMKA::new(
            provider.crypto(),
            ciphersuite,
            user.credential_with_key().credential.clone(),
            leaf_secret.clone().into(),
        )
        .map_err(|err| SumacError::MLSError(err))?;


        let mut diff = public_tree.empty_diff();
   
        // add the new leaf in the tree, by replacing the blank one
        let new_leaf_index = diff.add_leaf(new_leaf_node.clone().into()).unwrap();
        assert_eq!(new_leaf_index, own_leaf_node_index);
        // diff.update_leaf(new_leaf_node.into(), own_leaf_node_index);
        
        let path_indices = diff.filtered_direct_path(own_leaf_node_index);

        let path_secret = PathSecret::from(MlsSecret::from(leaf_secret.into())).derive_path_secret(provider.crypto(), ciphersuite).unwrap();

        let (path, _, _, commit_secret) =
            ParentNodeTMKA::derive_path(provider.crypto(), ciphersuite, path_secret, path_indices)
                .map_err(|err| SumacError::MLSError(err))?;

        diff.process_update_path(own_leaf_node_index, path)
            .expect("Failed to update path");

        public_tree.merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));

        Ok(Self {
            tree: public_tree,
            own_leaf_index: own_leaf_node_index,
            user: user.clone(),
            commit_secret: commit_secret.secret().into()
        })
    } 
}


impl TmkaSlaveGroup{
    pub(crate) fn generate_white_tree(&self, ciphersuite : Ciphersuite) -> TreeTMKA{
        let mut public_tree = self.tree.clone();
        let mut diff = public_tree.empty_diff();
        diff.whiten(ciphersuite);
        public_tree.merge_diff(diff.into_staged_diff().expect(""));
        public_tree
    }

    pub(crate) fn replace_leaf(&mut self, index: LeafNodeIndex, new_leaf_node: LeafNodeTMKA) {
        let mut diff = self.tree.empty_diff();

        diff.just_replace_leaf(new_leaf_node.into(), index);

        self.tree
            .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
    }


    pub(crate) fn replace_path(&mut self, leaf_index: LeafNodeIndex, path: Vec<(ParentNodeIndex, ParentNodeTMKA)>) -> Result<(), SumacError>{
        assert_eq!(leaf_index, self.own_leaf_index);
        let mut diff = self.tree.empty_diff();
        diff.process_update_path(leaf_index, path).map_err(|err| SumacError::MLSError(err))?;
        self.tree.merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
        Ok(())
    }



    pub fn add_placeholder_leaf(&mut self, ciphersuite : Ciphersuite) -> LeafNodeIndex{
        let mut diff = self.tree.empty_diff();
        let leaf_index = diff.add_leaf(LeafNodeTMKA::white(ciphersuite).into()).unwrap();
        self.tree.merge_diff(diff.into_staged_diff().unwrap());
        leaf_index

    }
}