use std::collections::HashSet;

use openmls::{
    prelude::{Ciphersuite, Credential, LeafNodeIndex, PathSecret},
    tree_sumac::{
        nodes::{
            encryption_keys::KeyPairRef,
            traits::{OptionNode, White},
        }, treekem::UpdatePath, LeafNodeTMKA, OptionLeafNodeTMKA, ParentNodeTMKA
    },
};
use openmls_traits::OpenMlsProvider;

use crate::{
    crypto::{hpke::hpke_encrypt_secret, secret::Secret},
    errors::SumacError,
    tmka::{CommitTMKABroadcast, CommitTMKAUnicast, TreeManager, TreeTMKA},
    Operation,
};

#[derive(Clone)]
pub struct TmkaAdminGroup {
    pub admin: TreeManager,
    pub tree: TreeTMKA,
    pub commit_secret: Secret,
}

impl TmkaAdminGroup {
    pub fn print_debug(&self, message: &str) {
        self.tree.print_debug(message);
    }

    pub fn commit(
        &mut self,
        op: Operation,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
    ) -> Result<(CommitTMKABroadcast, Option<CommitTMKAUnicast>), SumacError> {
        // arbre public: copier l'arbre courant et blanchir tous les noeuds avec des neouds par défaut.
        let public_tree = self.generate_white_tree(ciphersuite);

        let mut diff = self.tree.empty_diff();

        let (target_leaf_index, new_leaf) = match op.clone() {
            Operation::Add(user) => {
                // Create the leaf of the new user
                let key_package_new_user = user.key_package()?;

                let new_leaf = key_package_new_user.leaf_node_tmka().clone();

                // Add the new leaf node to the tree
                let new_leaf_index = diff.add_leaf(new_leaf.clone().into()).map_err(|_| {
                    SumacError::TrueSumacError(
                        "(A CHANGER): impossible d'ajouter la feuille dans l'arbre".to_owned(),
                    )
                })?;

                (new_leaf_index, Some(new_leaf))
            }
            Operation::Remove(user) => {
                //                 // Idem CGKA, just find the leaf and remove it. Also blank the path
                let leaf_index = self
                    .tree
                    .leaves()
                    .find_map(|(index, leaf)| {
                        leaf.node().clone().and_then(|actual_leaf| {
                            if actual_leaf.credential().serialized_content()
                                == Into::<Credential>::into(user.credential().clone())
                                    .serialized_content()
                            {
                                Some(index)
                            } else {
                                None
                            }
                        })
                    })
                    .ok_or(SumacError::TrueSumacError(
                        "Leaf to be removed not found".to_owned(),
                    ))?;
                diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), leaf_index);
                (leaf_index, None)
            }
            Operation::Update(user) => {
                let leaf_index = self
                    .tree
                    .leaves()
                    .find_map(|(index, leaf)| {
                        leaf.node().clone().and_then(|actual_leaf| {
                            if actual_leaf.credential().serialized_content()
                                == Into::<Credential>::into(user.credential().clone())
                                    .serialized_content()
                            {
                                Some(index)
                            } else {
                                None
                            }
                        })
                    })
                    .ok_or(SumacError::TrueSumacError(
                        "Leaf to be removed not found".to_owned(),
                    ))?;


                let new_leaf_secret = Secret::random(ciphersuite, provider.rand())?;
                let new_leaf_node = LeafNodeTMKA::new(provider.crypto(), ciphersuite, user.credential().clone().into(), new_leaf_secret.into()).map_err(|err| SumacError::MLSError(err))?;
                
                (leaf_index, Some(new_leaf_node))
            }
        };
        //         // Derive and apply an update path on the direct path of the new leaf
        let (plain_path, _, commit_secret) = diff
            .apply_own_update_path(
                provider,
                ciphersuite,
                target_leaf_index,
                new_leaf.clone().map(|leaf| leaf.into()),
                new_leaf.clone().map(|leaf| PathSecret::from(leaf.leaf_secret().clone())),
            )
            .expect("Failed to compute update path");

        self.commit_secret = commit_secret.secret().into();

        //         // Now we encrypt the path to the other members, using secret-key cryptography

        // Encrypt the path to the correct recipient nodes.
        let encrypted_path = diff
            .encrypt_path(
                provider.crypto(),
                ciphersuite,
                &plain_path,
                &HashSet::from_iter(vec![target_leaf_index].iter()), // no exclusion list in this case I think
                target_leaf_index,
            )
            .expect("Encryption of the path failed");

        let encrypted_path = UpdatePath::<LeafNodeTMKA, ParentNodeTMKA>::new(
            new_leaf.clone().unwrap_or(LeafNodeTMKA::white(ciphersuite)),
            encrypted_path,
        ); // the leaf node dos not matter here, it is not broacasted in TMKA

        // Ici juste extraire les path secret
        let encrypted_path_secrets = encrypted_path
            .nodes()
            .iter()
            .map(|node| {
                assert!(node.encrypted_path_secrets(1).is_none());
                node.encrypted_path_secrets(0).unwrap().clone()
            })
            .collect::<Vec<Vec<u8>>>();

        let broadcast = CommitTMKABroadcast {
            encrypted_path_secrets,
            updated_leaf_index: target_leaf_index,
            operation: op.clone(),
        };

        self.tree
            .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));

        let welcome = match op {
            Operation::Add(user) | Operation::Update(user) => {
                // Here, we are sure that there is a new leaf
                let new_leaf = new_leaf.unwrap();
                //Puis dans le process_welcome on remplacera les noeuds du path par les secrets dérivés
                let keypair = user.encryption_keypair()?;
                let public_key_new_user = keypair.public_key();

                let encrypted_leaf_secret = hpke_encrypt_secret(
                    provider,
                    ciphersuite,
                    &Secret::from(new_leaf.leaf_secret().clone()),
                    &public_key_new_user,
                )?;

                Some(CommitTMKAUnicast {
                    own_leaf_node_index: target_leaf_index,
                    encrypted_leaf_secret,
                    public_tree,
                })
            },
            _ => None,
        };

        Ok((broadcast, welcome))
    }
}

impl TmkaAdminGroup {
    pub(crate) fn replace_leaf(&mut self, index: LeafNodeIndex, new_leaf_node: LeafNodeTMKA) {
        let mut diff = self.tree.empty_diff();

        diff.just_replace_leaf(new_leaf_node.into(), index);

        self.tree
            .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
    }

    pub(crate) fn generate_white_tree(&self, ciphersuite: Ciphersuite) -> TreeTMKA {
        let mut public_tree = self.tree.clone();
        let mut diff = public_tree.empty_diff();
        diff.whiten(ciphersuite);
        public_tree.merge_diff(diff.into_staged_diff().expect(""));
        public_tree
    }
}
