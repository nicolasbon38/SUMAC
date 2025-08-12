use openmls::treesync::node::parent_node::UnmergedLeaves;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use openmls::ciphersuite::{self, Secret as MlsSecret};
use openmls::error::LibraryError;
use openmls::prelude::{
    Ciphersuite, Credential, HpkeCiphertext, LeafNodeIndex, OpenMlsCrypto, PathSecret,
};
use openmls::tree_sumac::nodes::encryption_keys::{KeyPairRef, PkeKeyPair, SymmetricKey};
use openmls::tree_sumac::nodes::traits::OptionNode;
use openmls::tree_sumac::treekem::{DecryptPathParams, UpdatePath};
use openmls::tree_sumac::{LeafNodeCGKA, NodeVariant, OptionLeafNodeCGKA, OptionParentNodeCGKA};
use openmls::tree_sumac::{ParentNodeCGKA, RatchetTree, SumacTree};
use openmls_traits::OpenMlsProvider;
use rand::rng;
use rand::seq::IteratorRandom;

use crate::crypto::hpke::{derive_hpke_keypair, hpke_decrypt_secret, hpke_encrypt_secret};
use crate::crypto::secret::Secret;
use crate::crypto::types::HPKEEncryptionKeyPair;
use crate::errors::SumacError;
use crate::test_utils::{
    check_sync_cgka, create_pool_of_users, create_user, process_broadcast_cgka, setup_provider,
    CIPHERSUITE,
};
use crate::user::User;
use crate::Operation;

pub type TreeCGKA = SumacTree<OptionLeafNodeCGKA, OptionParentNodeCGKA>;

#[derive(Clone)]
pub struct CGKAGroup {
    pub user: User,
    pub tree: TreeCGKA,
    pub encryption_keypairs: Vec<HPKEEncryptionKeyPair>,
    own_leaf_index: LeafNodeIndex,
    pub commit_secret: Secret,
}

impl User {
    pub fn create_group(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<CGKAGroup, SumacError> {
        let key_package = self.key_package()?;

        let tree = TreeCGKA::new(key_package.leaf_node_cgka().clone().into())
            .expect("Creation of the CGKA failed");

        Ok(CGKAGroup {
            tree,
            user: self.clone(),
            encryption_keypairs: vec![self.encryption_keypair()?],
            own_leaf_index: LeafNodeIndex::new(0),
            commit_secret: Secret::random(ciphersuite, provider.rand())?,
        })
    }
}

#[derive(Clone)]
pub struct CommitCGKABroadcast {
    encrypted_update_path: UpdatePath<LeafNodeCGKA, ParentNodeCGKA>,
    sender_leaf_index: LeafNodeIndex,
    updated_leaf_index: LeafNodeIndex,
    operation: Operation,
}

pub struct CommitCGKAUnicast {
    sender_index: LeafNodeIndex,
    new_member_index: LeafNodeIndex,
    public_tree: TreeCGKA,
    user: User,
    encrypted_secret: HpkeCiphertext,
}

impl CGKAGroup {
    pub fn print_debug(&self, message: &str) {
        self.tree.print_debug(message);
        println!("commit secret :{:?}", self.commit_secret);
        println!("--------------------------");
    }

    pub fn commit(
        &mut self,
        op: Operation,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
    ) -> Result<(CommitCGKABroadcast, Option<CommitCGKAUnicast>), SumacError> {
        let mut diff = self.tree.empty_diff();

        let target_leaf_index = match op.clone() {
            Operation::Add(user) => {
                // Create the leaf of the new user
                let key_package_new_user = user.key_package()?;

                let new_leaf = key_package_new_user.leaf_node_cgka().clone();

                let new_leaf_index = diff.add_leaf(new_leaf.into()).map_err(|_| {
                    SumacError::TrueSumacError(
                        "(A CHANGER): impossible d'ajouter la feuille dans l'arbre".to_owned(),
                    )
                })?;

                new_leaf_index
            }
            Operation::Remove(user) => {
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
                diff.blank_leaf(leaf_index);
                leaf_index
            }

            Operation::Update(user) => {
                // do nothing. Everything is carried on by the rest
                assert_eq!(user.credential(), self.user.credential());
                self.own_leaf_index
            }
        };

        let credential_with_key = self.user.credential_with_key().clone();

        self.user
            .generate_key_package_bundle(ciphersuite, provider)?;
        let new_keypair = self.user.encryption_keypair()?;

        let new_own_leaf = LeafNodeCGKA::new(credential_with_key, new_keypair.public_key().clone());

        // Derive and apply an update path based on its own leaf
        let (plain_path, new_keypairs, commit_secret) = diff
            .apply_own_update_path(
                provider,
                ciphersuite,
                self.own_leaf_index,
                Some(new_own_leaf.clone().into()),
                None, // in CGKA, there is no leaf secret
            )
            .expect("Failed to compute update path");

        self.commit_secret = commit_secret.secret().into();

        let exclusion_list = HashSet::new();
        // exclusion_list.insert(&target_leaf_index.unwrap());

        // Encrypt the path to the correct recipient nodes.
        let encrypted_path = diff
            .encrypt_path(
                provider.crypto(),
                ciphersuite,
                &plain_path,
                &exclusion_list,
                self.own_leaf_index,
            )
            .expect("Encryption of the path failed");

        let encrypted_path = UpdatePath::new(new_own_leaf, encrypted_path);

        // add the new keypairs of its path
        self.encryption_keypairs.extend(new_keypairs);
        // add the new keypair associated of its updated leaf
        self.encryption_keypairs.append(&mut vec![new_keypair]);

        let commit_broadcast = CommitCGKABroadcast {
            encrypted_update_path: encrypted_path,
            sender_leaf_index: self.own_leaf_index,
            updated_leaf_index: target_leaf_index,
            operation: op.clone(),
        };

        let welcome = match op {
            Operation::Add(user) => {
                // Retrieve the path secret
                let direct_path_position = diff
                    .subtree_root_position(self.own_leaf_index, target_leaf_index)
                    .map_err(|_| SumacError::TrueSumacError("No Subroot".to_owned()))?;

                let secret = plain_path
                    .get(direct_path_position)
                    .map(|pupn| Secret::from_slice(pupn.path_secret().clone().secret().as_slice()))
                    .ok_or(SumacError::TrueSumacError(
                        "Should be a path secret here.".to_owned(),
                    ))?;

                let keypair = user.encryption_keypair()?;
                let public_key = keypair.public_key();

                let encrypted_secret =
                    hpke_encrypt_secret(provider, ciphersuite, &secret, &public_key)?;

                self.tree
                    .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));

                Some(CommitCGKAUnicast {
                    sender_index: self.own_leaf_index,
                    new_member_index: target_leaf_index,
                    public_tree: self.tree.clone(),
                    user,
                    encrypted_secret,
                })
            }
            _ => {
                self.tree
                    .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
                None
            }
        };

        Ok((commit_broadcast, welcome))
    }

    pub fn process(
        &mut self,
        commit: &CommitCGKABroadcast,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(), SumacError> {
        let mut diff = self.tree.empty_diff();

        let CommitCGKABroadcast {
            encrypted_update_path,
            sender_leaf_index,
            updated_leaf_index,
            operation,
        } = commit;

        match operation {
            Operation::Add(user) => {
                let key_package = user.key_package()?;
                let new_leaf = key_package.leaf_node_cgka().clone();
                let new_index = diff
                    .add_leaf(new_leaf.into())
                    .expect("Failed to add the new node while processing the broadcast");
                assert_eq!(new_index, *updated_leaf_index);
            }
            Operation::Remove(_) => {
                diff.blank_leaf(*updated_leaf_index);
            }
            Operation::Update(_) => {
                //nothing to do
            }
        };

        diff.apply_received_update_path(
            provider.crypto(),
            ciphersuite,
            *sender_leaf_index,
            &encrypted_update_path,
        )
        .expect("Application of the received path did not work");

        let exclusion_list = HashSet::new();
        //     exclusion_list.insert(&sender_leaf_index);

        let params_for_decryption = DecryptPathParams {
            update_path: encrypted_update_path.nodes(),
            sender_leaf_index: *sender_leaf_index,
            exclusion_list: &exclusion_list,
        };

        let (new_encryption_keypairs, commit_secret) = diff
            .decrypt_path(
                provider.crypto(),
                ciphersuite,
                params_for_decryption,
                &self
                    .encryption_keypairs
                    .iter()
                    .collect::<Vec<&HPKEEncryptionKeyPair>>()
                    .as_slice(),
                self.own_leaf_index,
            )
            .map_err(|e| SumacError::MLSError(e))?;

        self.encryption_keypairs.extend(new_encryption_keypairs);
        self.commit_secret = commit_secret.secret().into();
        self.tree
            .merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
        Ok(())
    }

    pub fn process_welcome(
        commit: CommitCGKAUnicast,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        user_processing: &User,
    ) -> Result<Self, SumacError> {
        let CommitCGKAUnicast {
            sender_index,
            new_member_index,
            public_tree,
            user,
            encrypted_secret,
        } = commit;

        assert_eq!(user.identity(), user_processing.identity());

        let personal_keypair = user.encryption_keypair()?;
        let private_key = personal_keypair.private_key();

        let path_secret =
            hpke_decrypt_secret(provider, ciphersuite, &encrypted_secret, &private_key)?;

        let (encryption_keypairs, commit_secret) = public_tree
            .derive_path_secrets(
                provider.crypto(),
                ciphersuite,
                path_secret.as_slice(),
                sender_index,
                new_member_index,
            )
            .expect("Derivation of secrets in the welcome failed");

        let mut owned_keypairs = vec![user.encryption_keypair()?];
        owned_keypairs.extend(encryption_keypairs);

        Ok(Self {
            user,
            tree: public_tree,
            encryption_keypairs: owned_keypairs,
            own_leaf_index: new_member_index,
            commit_secret: commit_secret.secret().into(),
        })
    }
}

impl CGKAGroup {
    pub fn derive_group_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<SymmetricKey, SumacError> {
        SymmetricKey::derive_from_path_secret(
            crypto,
            ciphersuite,
            &PathSecret::from(MlsSecret::from_slice(self.commit_secret.as_slice())),
        )
        .map_err(|err| SumacError::MLSError(err))
    }
}

#[test]
fn test_cgka() {
    let mut rng = rng();

    let n_users = 20;
    let provider = setup_provider();
    let all_users = create_pool_of_users(n_users, &provider, "User".to_owned());
    let mut all_groups = HashMap::<String, CGKAGroup>::new();

    let user_0 = all_users.get("User_0").unwrap();
    all_groups.insert(
        "User_0".to_owned(),
        user_0.create_group(&provider, CIPHERSUITE).unwrap(),
    );

    let mut committer_name = String::from("User_0");

    (0..n_users)
        .skip(1)
        .map(|i| format!("User_{i}"))
        .for_each(|username| {
            println!("Adding {username}");
            let new_user = all_users.get(&username).unwrap();
            let (broadcast, welcome) = all_groups
                .get_mut(&committer_name)
                .unwrap()
                .commit(Operation::Add(new_user.clone()), CIPHERSUITE, &provider)
                .unwrap();

            // process the broadcast
            process_broadcast_cgka(
                &mut all_groups,
                broadcast,
                &committer_name,
                None,
                &provider,
                CIPHERSUITE,
            )
            .unwrap();

            // process the welcome
            let new_group = CGKAGroup::process_welcome(
                welcome.expect("sHOULD BE A WELCOME"),
                &provider,
                CIPHERSUITE,
                &new_user,
            )
            .unwrap();

            all_groups.insert(username.clone(), new_group);

            committer_name = all_groups.keys().choose(&mut rng).unwrap().to_string();
            all_groups
                .iter()
                .for_each(|(username, group)| group.print_debug(&format!("View of {}", username)));
            check_sync_cgka(
                &all_groups
                    .iter()
                    .map(|(_, group)| group.clone())
                    .collect::<Vec<CGKAGroup>>(),
            );
        });

    for _ in 0..n_users {
        committer_name = all_groups.keys().choose(&mut rng).unwrap().to_string();
        let committer = all_users.get(&committer_name).unwrap();

        let (broadcast, _) = all_groups
            .get_mut(&committer_name)
            .unwrap()
            .commit(Operation::Update(committer.clone()), CIPHERSUITE, &provider)
            .unwrap();

        // process the broadcast
        process_broadcast_cgka(
            &mut all_groups,
            broadcast,
            &committer_name,
            None,
            &provider,
            CIPHERSUITE,
        )
        .unwrap();

        all_groups
            .iter()
            .for_each(|(username, group)| group.print_debug(&format!("View of {}", username)));
        check_sync_cgka(
            &all_groups
                .iter()
                .map(|(_, group)| group.clone())
                .collect::<Vec<CGKAGroup>>(),
        );
    }


    for _ in 0..n_users - 3{
        let username_to_delete = all_groups.keys().choose(&mut rng).unwrap().clone();
        let committer_name = all_groups.keys().filter(|name| **name != username_to_delete).choose(&mut rng).unwrap().clone();
        println!("Removing {username_to_delete}. COmmitter is {committer_name}");
        let user_to_delete = all_users.get(&username_to_delete).unwrap();
        let (broadcast, _) = all_groups
            .get_mut(&committer_name)
            .unwrap()
            .commit(
                Operation::Remove(user_to_delete.clone()),
                CIPHERSUITE,
                &provider,
            )
            .unwrap();

        // process the broadcast
        process_broadcast_cgka(
            &mut all_groups,
            broadcast,
            &committer_name,
            Some(&username_to_delete),
            &provider,
            CIPHERSUITE,
        )
        .unwrap();

        all_groups.remove(&username_to_delete);

        all_groups
            .iter()
            .for_each(|(username, group)| group.print_debug(&format!("View of {}", username)));
        check_sync_cgka(
            &all_groups
                .iter()
                .map(|(_, group)| group.clone())
                .collect::<Vec<CGKAGroup>>(),
        );
    }

    println!("Final state of all the trees");
    all_groups
        .iter()
        .for_each(|(username, group)| group.print_debug(&format!("View of {}", username)));

    check_sync_cgka(
        &all_groups
            .into_iter()
            .map(|(_, group)| group)
            .collect::<Vec<CGKAGroup>>(),
    );
}

impl CGKAGroup {
    pub fn generate_random_group(
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        all_users: &HashMap<String, User>,
        prefix_user: String
    ) -> Result<HashMap<String, Self>, SumacError> {
        let n_users = all_users.len();
        let n_nodes = 2 * n_users - 1;

        let mut vector_nodes = Vec::with_capacity(n_nodes);
        let mut keypairs_parents = Vec::with_capacity(n_nodes - n_users);
        for i in 0..n_nodes {
            if i % 2 == 0 {
                //leaf
                let username = format!("{}_{}", prefix_user, i / 2);
                let user = all_users.get(&username).expect(&format!("{} not in the pool", username));
                let leaf_node = LeafNodeCGKA::new(
                    user.credential_with_key().clone(),
                    user.encryption_keypair()?.public_key().clone(),
                );
                vector_nodes.push(Some(NodeVariant::Left(leaf_node)));
            } else {
                // parent
                let keypair = PkeKeyPair::random(provider.rand(), provider.crypto(), ciphersuite)
                    .map_err(|err| SumacError::MLSError(err))?;
                let parent_node = ParentNodeCGKA {
                    encryption_key: keypair.public_key().clone(),
                    unmerged_leaves: UnmergedLeaves::new(),
                };
                vector_nodes.push(Some(NodeVariant::Right(parent_node)));
                keypairs_parents.push(keypair);
            }
        }
        let ratchet_tree = RatchetTree::<LeafNodeCGKA, ParentNodeCGKA>::new(vector_nodes);
        let tree = TreeCGKA::from_ratchet_tree(ratchet_tree);

        let mut all_groups = HashMap::new();
        let commit_secret = Secret::random(ciphersuite, provider.rand())?;
        // manage key ownership
        for i in 0..n_users {
            let username = format!("{}_{}", prefix_user, i);
            let user = all_users.get(&username).unwrap();
            let mut owned_keys: Vec<PkeKeyPair> = vec![user.encryption_keypair()?];

            let diff = tree.empty_diff();
            let path = diff.filtered_direct_path(LeafNodeIndex::new(i.try_into().unwrap()));

            for index in path {
                owned_keys.push(keypairs_parents.get(index.usize()).unwrap().clone())
            }

            let group = CGKAGroup {
                user: user.clone(),
                tree: tree.clone(),
                encryption_keypairs: owned_keys,
                own_leaf_index: LeafNodeIndex::new(i.try_into().unwrap()),
                commit_secret: commit_secret.clone(),
            };

            all_groups.insert(username, group);
        }
        Ok(all_groups)
    }
}

#[test]
fn test_create_large_cgka() {
    let mut rng = rng();

    let n_users = 20;
    let provider = setup_provider();
    let mut all_users = create_pool_of_users(n_users, &provider, "User".to_owned());

    let mut all_groups = CGKAGroup::generate_random_group(&provider, CIPHERSUITE, &all_users, "User".to_string()).unwrap();

    check_sync_cgka(
        &all_groups
            .iter()
            .map(|(_, group)| group.clone())
            .collect::<Vec<CGKAGroup>>(),
    );


    let committer_name = all_groups.keys().choose(&mut rng).unwrap().to_string();

    let new_username = format!("User_{}", n_users);
    let new_user = create_user(new_username.clone(), &provider);
    all_users.insert(new_username.clone(), new_user.clone());

    let (commit_broadcast, commit_unicast) = all_groups.get_mut(&committer_name).unwrap().commit(Operation::Add(new_user.clone()), CIPHERSUITE,  &provider).unwrap();

    process_broadcast_cgka(&mut all_groups, commit_broadcast, &committer_name, None, &provider, CIPHERSUITE).unwrap();

    let new_group = CGKAGroup::process_welcome(commit_unicast.unwrap(), &provider, CIPHERSUITE, &new_user).unwrap();

    all_groups.insert(new_username, new_group);

    check_sync_cgka(
        &all_groups
            .into_iter()
            .map(|(_, group)| group)
            .collect::<Vec<CGKAGroup>>(),
    );
}





