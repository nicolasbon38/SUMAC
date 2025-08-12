use std::collections::HashMap;

use openmls::{
    prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex, PathSecret, Secret as MlsSecret},
    tree_sumac::{
        nodes::encryption_keys::PkeKeyPair, LeafNodeTMKA, NodeVariant, OptionLeafNodeTMKA,
        OptionParentNodeTMKA, ParentNodeTMKA, RatchetTree, SumacTree,
    },
    treesync::node::parent_node::UnmergedLeaves,
};

use openmls_traits::OpenMlsProvider;
use rand::{rng, seq::IteratorRandom};

use crate::{
    crypto::secret::Secret,
    errors::SumacError,
    test_utils::{
        check_sync_tmka, create_pool_of_users, create_user, process_broadcast_tmka, setup_provider,
        CIPHERSUITE,
    },
    tmka::{admin_group::TmkaAdminGroup, user_group::TmkaSlaveGroup},
    user::User,
    Operation,
};

pub mod admin_group;
pub mod user_group;

pub type TreeManager = User;

pub type TreeTMKA = SumacTree<OptionLeafNodeTMKA, OptionParentNodeTMKA>;

impl TreeManager {
    pub fn create_tmka_group(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        first_user: &User,
    ) -> Result<(TmkaAdminGroup, TmkaSlaveGroup), SumacError> {
        let leaf_secret = Secret::random(ciphersuite, provider.rand())?;

        let leaf_node = LeafNodeTMKA::new(
            provider.crypto(),
            ciphersuite,
            first_user.credential_with_key().credential.clone(),
            leaf_secret.clone().into(),
        )
        .map_err(|err| SumacError::MLSError(err))?;

        let commit_secret = leaf_secret.derive_secret(provider.crypto(), ciphersuite)?;

        let tree = TreeTMKA::new(leaf_node.into()).map_err(|err| SumacError::MLSError(err))?;

        Ok((
            TmkaAdminGroup {
                admin: self.clone(),
                tree: tree.clone(),
                commit_secret: commit_secret.clone(),
            },
            TmkaSlaveGroup {
                tree,
                own_leaf_index: LeafNodeIndex::new(0),
                user: first_user.clone(),
                commit_secret,
            },
        ))
    }
}

#[derive(Clone)]
pub struct CommitTMKABroadcast {
    encrypted_path_secrets: Vec<Vec<u8>>,
    updated_leaf_index: LeafNodeIndex, // updated leaf index
    operation: Operation,
}

pub struct CommitTMKAUnicast {
    own_leaf_node_index: LeafNodeIndex,
    encrypted_leaf_secret: HpkeCiphertext,
    public_tree: TreeTMKA,
} // In TMKA, users only need to know their leaf secret when they enter in the tree, as well as thu dumb ratchet tree to know the layout

impl CommitTMKAUnicast {
    pub fn own_leaf_index(&self) -> &LeafNodeIndex {
        &self.own_leaf_node_index
    }
}

#[test]
fn test_tmka() {
    let mut rng = rng();

    let n_users = 5;
    let provider = setup_provider();
    let all_users = create_pool_of_users(n_users, &provider, "User".to_owned());
    let admin = create_user("Admin".to_owned(), &provider);
    let mut all_user_groups = HashMap::<String, TmkaSlaveGroup>::new();

    let user_0 = all_users.get("User_0").unwrap();
    let (mut admin_group, first_user_group) = admin
        .create_tmka_group(&provider, CIPHERSUITE, user_0)
        .unwrap();

    all_user_groups.insert("User_0".to_owned(), first_user_group);

    admin_group.print_debug("At creation:");

    (0..n_users)
        .skip(1)
        .map(|i| format!("User_{i}"))
        .for_each(|username| {
            let new_user = all_users.get(&username).unwrap();

            let (broadcast, welcome) = admin_group
                .commit(Operation::Add(new_user.clone()), CIPHERSUITE, &provider)
                .unwrap();

            process_broadcast_tmka(
                &mut all_user_groups,
                broadcast,
                None,
                &provider,
                CIPHERSUITE,
            )
            .unwrap();

            // process the welcome
            let new_group = TmkaSlaveGroup::process_welcome(
                welcome.expect("sHOULD BE A WELCOME"),
                &provider,
                CIPHERSUITE,
                &new_user,
            )
            .unwrap();

            all_user_groups.insert(username.clone(), new_group);
            let check = check_sync_tmka(
                &admin_group,
                all_user_groups
                    .iter()
                    .map(|(_, group)| group)
                    .collect::<Vec<_>>(),
            );
            if !check {
                println!("Final state of all the trees");
                admin_group.print_debug("view of admin:");
                all_user_groups.iter().for_each(|(username, group)| {
                    group.print_debug(&format!("View of {}", username))
                });
                panic!()
            }
        });

    // for _ in 0..n_users - 1{
    //     let username_to_update = all_user_groups.keys().choose(&mut rng).unwrap().clone();
    //     let user_to_update = all_users.get(&username_to_update).unwrap();

    //     println!("Updating {username_to_update}");
    //     let (broadcast, _) = admin_group.commit(
    //         Operation::Update(user_to_update.clone()),
    //         CIPHERSUITE,
    //         &provider,
    //     ).unwrap();

    //     process_broadcast_tmka(
    //         &mut all_user_groups,
    //         broadcast,
    //         None,
    //         &provider,
    //         CIPHERSUITE,
    //     ).unwrap();

    //     let check = check_sync_tmka(&admin_group, all_user_groups.iter().map(|(_, group)| group).collect::<Vec<_>>());
    //     if !check{
    //         println!("Final state of all the trees");
    //         admin_group.print_debug("view of admin:");
    //         all_user_groups.iter().for_each(|(username, group)| group.print_debug(&format!("View of {}", username)));
    //         panic!() 
    //     }
    // }

    // for _ in (0..n_users - 3) {
    //     let username_to_delete = all_user_groups.keys().choose(&mut rng).unwrap().clone();
    //     println!("Removing {username_to_delete}");
    //     let user_to_delete = all_users.get(&username_to_delete).unwrap();

    //     let (broadcast, _) = admin_group
    //         .commit(
    //             Operation::Remove(user_to_delete.clone()),
    //             CIPHERSUITE,
    //             &provider,
    //         )
    //         .unwrap();

    //     process_broadcast_tmka(
    //         &mut all_user_groups,
    //         broadcast,
    //         Some(&username_to_delete),
    //         &provider,
    //         CIPHERSUITE,
    //     )
    //     .unwrap();

    //     all_user_groups.remove(&username_to_delete);

    //     let check = check_sync_tmka(
    //         &admin_group,
    //         all_user_groups
    //             .iter()
    //             .map(|(_, group)| group)
    //             .collect::<Vec<_>>(),
    //     );
    //     if !check {
    //         println!("Final state of all the trees");
    //         admin_group.print_debug("view of admin:");
    //         all_user_groups
    //             .iter()
    //             .for_each(|(username, group)| group.print_debug(&format!("View of {}", username)));
    //         panic!()
    //     }
    // }
}

pub fn generate_random_tmka(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    admin: &User,
    all_users: &HashMap<String, User>,
) -> Result<(TmkaAdminGroup, HashMap<String, TmkaSlaveGroup>), SumacError> {

    let n_users = all_users.len();
    let n_nodes = 2 * n_users - 1;

    let mut vector_nodes = Vec::with_capacity(n_nodes);

    for i in 0..n_nodes {
        if i % 2 == 0 {
            // leaf
            let username = format!("User_{}", i / 2);
            let user = all_users.get(&username).unwrap();
            let leaf_secret = Secret::random(ciphersuite, provider.rand())?;
            let leaf_node = LeafNodeTMKA::new(
                provider.crypto(),
                ciphersuite,
                user.credential_with_key().credential.clone(),
                leaf_secret.into(),
            )
            .map_err(|err| SumacError::MLSError(err))?;
            vector_nodes.push(Some(NodeVariant::Left(leaf_node)));
        } else {
            let path_secret = Secret::random(ciphersuite, provider.rand())?;
            let parent_node = ParentNodeTMKA::new_from_path_secret(
                provider.crypto(),
                ciphersuite,
                PathSecret::from(MlsSecret::from(path_secret.into())),
                None,
            )
            .map_err(|e| SumacError::MLSError(e))?;
            vector_nodes.push(Some(NodeVariant::Right(parent_node)));
        }
    }

    let ratchet_tree = RatchetTree::<LeafNodeTMKA, ParentNodeTMKA>::new(vector_nodes.clone());
    let tree = TreeTMKA::from_ratchet_tree(ratchet_tree);
    let commit_secret = Secret::random(ciphersuite, provider.rand())?;

    let mut all_user_groups = HashMap::new();

    for i in 0..n_users {
        let username = format!("User_{}", i);
        let user = all_users.get(&username).unwrap();

        let mut user_tree = tree.clone();

        let mut diff = user_tree.empty_diff();
        diff.whiten(ciphersuite);

        let path = diff.filtered_direct_path(LeafNodeIndex::new(i.try_into().unwrap()));

        for index_parent in path {
            let index_parent_in_vec = index_parent.usize() * 2 + 1;
            let filled_parent = vector_nodes.get(index_parent_in_vec).unwrap().clone().unwrap();

            match filled_parent {
                either::Either::Left(_) => panic!(),
                either::Either::Right(parent) => {
                    diff.just_replace_parent(parent.into(), index_parent)
                }
            };
        }

        let index_leaf_in_vec = 2 * i;
        let filled_leaf = vector_nodes.get(index_leaf_in_vec).unwrap().clone().unwrap();
        match filled_leaf {
            either::Either::Left(leaf) => {
                diff.just_replace_leaf(leaf.into(), LeafNodeIndex::new(i.try_into().unwrap()))
            }
            either::Either::Right(_) => panic!(),
        }

        user_tree.merge_diff(diff.into_staged_diff().unwrap());

        let user_group = TmkaSlaveGroup {
            tree: user_tree,
            own_leaf_index: LeafNodeIndex::new(i.try_into().unwrap()),
            user: user.clone(),
            commit_secret: commit_secret.clone(),
        };
        all_user_groups
            .insert(username, user_group);
    }

    let admin_group = TmkaAdminGroup {
        admin: admin.clone(),
        tree,
        commit_secret,
    };

    Ok((admin_group, all_user_groups))
}



#[test]
fn test_create_large_tmka() {
    let mut rng = rng();

    let n_users = 20;
    let provider = setup_provider();
    let mut all_users = create_pool_of_users(n_users, &provider, "User".to_owned());

    let admin = create_user("Admin".to_string(), &provider);

    let (mut admin_group, mut all_user_groups) = generate_random_tmka(&provider, CIPHERSUITE, &admin,  &all_users).unwrap();

    assert!(check_sync_tmka(&admin_group, all_user_groups.iter().map(|(_, group)| group).collect::<Vec<_>>()));
    


    // let username_to_delete = format!("User_3");
    // let user_to_delete = all_users.get(&username_to_delete).unwrap();

    // let (commit_broadcast, _) = admin_group.commit(Operation::Remove(user_to_delete.clone()), CIPHERSUITE,  &provider).unwrap();

    // process_broadcast_tmka(&mut all_user_groups, commit_broadcast, Some("User_3"), &provider, CIPHERSUITE).unwrap();

    // assert!(check_sync_tmka(&admin_group, all_user_groups.iter().map(|(_, group)| group).collect::<Vec<_>>()));



    let new_username = format!("User_{}", n_users);
    let new_user = create_user(new_username.clone(), &provider);
    all_users.insert(new_username.clone(), new_user.clone());

    let (commit_broadcast, commit_unicast) = admin_group.commit(Operation::Add(new_user.clone()), CIPHERSUITE,  &provider).unwrap();

    process_broadcast_tmka(&mut all_user_groups, commit_broadcast, None, &provider, CIPHERSUITE).unwrap();

    let new_group = TmkaSlaveGroup::process_welcome(commit_unicast.unwrap(), &provider, CIPHERSUITE, &new_user).unwrap();

    all_user_groups.insert(new_username, new_group);

    assert!(check_sync_tmka(&admin_group, all_user_groups.iter().map(|(_, group)| group).collect::<Vec<_>>()));



}