use openmls::{
    prelude::{Ciphersuite, Secret as MlsSecret},
    tree_sumac::{
        nodes::encryption_keys::{KeyPairRef, SymmetricKey},
        LeafNodeTMKA, ParentNodeTMKA,
    },
};
use openmls_traits::OpenMlsProvider;

use crate::{
    cgka::{CGKAGroup, CommitCGKABroadcast, CommitCGKAUnicast},
    crypto::{secret::Secret, types::AeadCiphertext},
    errors::SumacError,
    sumac::{
        regeneration::{EncryptedRegenerationTree, RegenerationTree},
        sumac_operations::op_user::{AdminName, UserName},
        SumacAdminGroup, SumacState, SumacUserGroup,
    },
    tmka::{admin_group::TmkaAdminGroup, user_group::TmkaSlaveGroup, TreeTMKA},
    Operation,
};

pub fn op_admin_committer(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: &AdminName,
) -> Result<
    (
        CommitCGKABroadcast,
        Option<CommitCGKAUnicast>,
        Option<EncryptedRegenerationTree>,
        AeadCiphertext,
    ),
    SumacError,
> {
    let group_committer = state
        .all_admin_groups
        .get_mut(username_committer)
        .expect("The committter has no group");

    // The committter commits in the admin CGKA
    let (commit_broadcast_cgka, commit_unicast_cgka_admin) =
        group_committer
            .cgka_mut()
            .commit(op.clone(), ciphersuite, provider)?;

    // derive a new group key from the admin key
    let group_key = group_committer.update_group_key_from_cgka(provider, ciphersuite)?;

    //encrypted the group key under the commtitter's tree key
    let root_key = &group_committer.tmka().group_key;
    let encrypted_group_key =
        root_key.encrypt(provider.crypto(), group_key.as_slice())?;

    // generation of the regeneration set (not for Remove), and encryption
    let encrypted_regeneration_tree = match op {
        Operation::Add(admin) | Operation::Update(admin) => {
            let regeneration_tree = group_committer
                .tmka()
                .build_regeneration_tree(provider, ciphersuite);
            Some(regeneration_tree.encrypt_hpke(
                provider,
                ciphersuite,
                admin.encryption_keypair()?.public_key(),
            ))
        }
        Operation::Remove(_) => {
            // nothing to do
            None
        }
    };

    Ok((
        commit_broadcast_cgka,
        commit_unicast_cgka_admin,
        encrypted_regeneration_tree,
        encrypted_group_key,
    ))
}

pub fn op_admin_other_admins(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    commit_broadcast_cgka: &CommitCGKABroadcast,
    username_committer: &AdminName,
    username_target_admin: &AdminName,
) -> Result<(), SumacError> {
    for (admin_name, admin_group) in state.all_admin_groups.iter_mut() {
        if (admin_name != username_committer) && (admin_name != username_target_admin) {
            op_admin_one_other_admin(provider, ciphersuite, admin_group, commit_broadcast_cgka)?;
        }
    }
    Ok(())
}

pub fn op_admin_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    admin_group: &mut SumacAdminGroup,
    commit_broadcast_cgka: &CommitCGKABroadcast,
) -> Result<(), SumacError> {
    // process the commit
    admin_group
        .cgka_mut()
        .process(commit_broadcast_cgka, provider, ciphersuite)?;
    // update the group key from the admin key
    admin_group.update_group_key_from_cgka(provider, ciphersuite)?;
    Ok(())
}

pub fn op_admin_standard_users(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    encrypted_group_key: &AeadCiphertext,
    username_committer: &AdminName,
) -> Result<(), SumacError> {
    for (_, user_group) in state.all_user_groups.iter_mut() {
        op_admin_one_standard_user(
            op,
            provider,
            ciphersuite,
            user_group,
            encrypted_group_key,
            username_committer,
        )?;
    }
    Ok(())
}

pub fn op_admin_one_standard_user(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    encrypted_group_key: &AeadCiphertext,
    username_committer: &AdminName,
) -> Result<(), SumacError> {
    // Retrieves the key of the committer's tmka
    let encryption_key = &user_group
        .forest()
        .get(username_committer)
        .expect("The committer is supposed to have a tree un the user's forest")
        .group_key;

    // Decrypts the encrypted group key
    let group_key = SymmetricKey::from_vec(
        encryption_key.decrypt(provider.crypto(), encrypted_group_key)?,
        ciphersuite,
    );

    //updates it
    user_group.sumac_group_key = group_key;

    // Regeneration procedure

    match op {
        Operation::Add(admin) => {
            let tree_committer = user_group.forest().get(username_committer).unwrap();
            let own_leaf_node_index = tree_committer.own_leaf_index;

            let regeneration_set = tree_committer.build_regeneration_path(
                provider,
                ciphersuite,
                &own_leaf_node_index,
                true,
            );

            //create a white tree and a new group, for now dumb
            let new_tree = tree_committer.generate_white_tree(ciphersuite);
            let mut new_group = TmkaSlaveGroup {
                tree: new_tree,
                own_leaf_index: own_leaf_node_index,
                user: admin.clone(),
                commit_secret: Secret::zero(ciphersuite),
                group_key: SymmetricKey::derive_from_secret(
                    provider.crypto(),
                    ciphersuite,
                    &Secret::zero(ciphersuite).into(),
                )
                .unwrap(),
            };

            //replace the path by the content of the regeneration set
            let new_path = regeneration_set
                .secrets()
                .into_iter()
                .map(|(index, path_secret)| {
                    (
                        *index,
                        ParentNodeTMKA::new_from_path_secret(
                            provider.crypto(),
                            ciphersuite,
                            path_secret.clone(),
                            None,
                        )
                        .unwrap(),
                    )
                })
                .collect();
            new_group.replace_path(own_leaf_node_index, new_path)?;

            // also replace the leaf
            let new_leaf = LeafNodeTMKA::new(
                provider.crypto(),
                ciphersuite,
                admin.credential_with_key().credential.clone(),
                Into::<MlsSecret>::into(regeneration_set.leaf_secret().unwrap().clone()),
            )
            .unwrap();
            new_group.replace_leaf(own_leaf_node_index, new_leaf);

            //insert the new tree in the forest
            let res = user_group
                .forest_mut()
                .insert(admin.identity(), new_group)
                .is_none();
            assert!(res);
        }
        Operation::Update(admin_updated) => {
            let tree_committer = user_group.forest().get(username_committer).unwrap();
            let own_leaf_node_index = tree_committer.own_leaf_index;

            let regeneration_set = tree_committer.build_regeneration_path(
                provider,
                ciphersuite,
                &own_leaf_node_index,
                true,
            );

            let tree_admin_updated = user_group.forest_mut().get_mut(&admin_updated.identity()).unwrap();

            tree_admin_updated.commit_secret = tree_admin_updated.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
        },
        Operation::Remove(admin) => {
            // Just remove the tree of the target admin
            user_group.forest_mut().remove(&admin.identity());
        }
    }
    Ok(())
}

pub fn op_admin_target_admin(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    commit_broadcast_cgka_admin: CommitCGKABroadcast,   // for updates
    commit_unicast_cgka_admin: Option<CommitCGKAUnicast>,   // for add
    encrypted_regeneration_tree: Option<EncryptedRegenerationTree>,
) -> Result<Option<SumacAdminGroup>, SumacError> {
    let result = match op {
        Operation::Add(admin) => {
            let cgka = CGKAGroup::process_welcome(
                commit_unicast_cgka_admin.expect("Should be a welcome"),
                provider,
                ciphersuite,
                admin,
            )?;

            let keypair_new_admin = admin.encryption_keypair()?;
            let private_key_new_admin = keypair_new_admin.private_key();
            let regeneration_tree = RegenerationTree::decrypt_hpke(
                provider,
                ciphersuite,
                private_key_new_admin,
                encrypted_regeneration_tree.expect("In an add, there should b e"),
            );

            let tree_tmka = TreeTMKA::from_ratchet_tree(regeneration_tree.tree);

            let tmka = TmkaAdminGroup {
                admin: admin.clone(),
                tree: tree_tmka,
                commit_secret: Secret::zero(ciphersuite), // for now the commit secret is zero. It will get updated the next operation
                group_key: SymmetricKey::derive_from_secret(
                    provider.crypto(),
                    ciphersuite,
                    &Secret::zero(ciphersuite).into(),
                )
                .unwrap(),
            };

            let sumac_group_key = cgka.group_key.clone();

            let new_admin_group = SumacAdminGroup {
                _identifier: admin.identity(),
                cgka,
                tmka,
                sumac_group_key,
            };

            Some(new_admin_group)
        }
        Operation::Update(admin_updated) => {
            // retrieve the group to update
            let updated_group = state.all_admin_groups.get_mut(&admin_updated.identity()).expect("The updated admin has no group");

            updated_group.cgka_mut().process_own_update(provider, ciphersuite, admin_updated, commit_broadcast_cgka_admin)?;

            let keypair_updated_admin = admin_updated.encryption_keypair()?;
            let private_key_new_admin = keypair_updated_admin.private_key();
            let regeneration_tree = RegenerationTree::decrypt_hpke(
                provider,
                ciphersuite,
                private_key_new_admin,
                encrypted_regeneration_tree.expect("In an add, there should b e"),
            );

            let tmka_to_update = updated_group.tmka_mut();

            tmka_to_update.commit_secret = tmka_to_update.absorb_regeneration_tree(provider, ciphersuite, regeneration_tree)?;

            None
            
        },
        Operation::Remove(_) => None,
    };

    Ok(result)
}

pub fn full_op_admin(
    op: Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: AdminName,
    username_target_admin: UserName,
) -> Result<(), SumacError> {
    //////Committer's View/////////
    let (
        commit_broadcast_cgka,
        commit_unicast_cgka,
        encrypted_regeneration_tree,
        encrypted_group_key,
    ) = op_admin_committer(&op, provider, ciphersuite, state, &username_committer)?;

    // //////////////////////////////////Other Admins' view////////////////////////////
    op_admin_other_admins(
        provider,
        ciphersuite,
        state,
        &commit_broadcast_cgka,
        &username_committer,
        &username_target_admin,
    )?;

    // ////////////////////////////Standard Users' view////////////////////////////////
    op_admin_standard_users(
        &op,
        provider,
        ciphersuite,
        state,
        &encrypted_group_key,
        &username_committer,
    )?;

    ///////////////////////////////New User's view////////////////////////////////////:
    let new_admin_group = op_admin_target_admin(
        &op,
        provider,
        ciphersuite,
        state,
        commit_broadcast_cgka,
        commit_unicast_cgka,
        encrypted_regeneration_tree,
    )?;

    // Update the state
    match op {
        Operation::Add(_) => {
            assert!(new_admin_group.is_some());
            state
                .all_admin_groups
                .insert(username_target_admin.to_string(), new_admin_group.unwrap());
        }
        Operation::Remove(_) => {
            state.all_admin_groups.remove(&username_target_admin);
        }
        Operation::Update(_) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::{
        sumac::{create_large_sumac_group, sumac_operations::op_admin::full_op_admin},
        test_utils::{
            check_sync_sumac, create_pool_of_users, create_user, setup_provider, CIPHERSUITE,
        },
        Operation,
    };

    #[test]
    fn test_add_admin() {
        let provider = setup_provider();
        let ciphersuite = CIPHERSUITE;

        let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
        let all_users = create_pool_of_users(10, &provider, "User".to_string());

        let mut state =
            create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();
        let committer_name = "Admin_0".to_string();

        let new_admin_name = "Admin_10".to_string();
        let new_admin = create_user(new_admin_name.clone(), &provider);
        state
            .all_admins
            .insert(new_admin_name.clone(), new_admin.clone());

        full_op_admin(
            Operation::Add(new_admin),
            &provider,
            ciphersuite,
            &mut state,
            committer_name,
            new_admin_name,
        )
        .unwrap();

        check_sync_sumac(&state);
    }

    #[test]
    fn test_remove_admin() {
        let provider = setup_provider();
        let ciphersuite = CIPHERSUITE;

        let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
        let all_users = create_pool_of_users(10, &provider, "User".to_string());

        let mut state =
            create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();

        let committer_name = "Admin_0".to_string();
        let admin_to_remove = state.all_admins.get("Admin_7").unwrap();

        full_op_admin(
            Operation::Remove(admin_to_remove.clone()),
            &provider,
            ciphersuite,
            &mut state,
            committer_name,
            "Admin_7".to_string(),
        )
        .unwrap();

        check_sync_sumac(&state);
    }

    // #[test]
    // fn test_update_admin() {
    //     let provider = setup_provider();
    //     let ciphersuite = CIPHERSUITE;

    //     let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
    //     let all_users = create_pool_of_users(10, &provider, "User".to_string());

    //     let mut state =
    //         create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();

    //     let committer_name = "Admin_0".to_string();
    //     let admin_to_update = state.all_admins.get_mut("Admin_7").unwrap();

    //     // Update the key
    //     admin_to_update.generate_key_package_bundle(ciphersuite, &provider).unwrap();

    //     full_op_admin(
    //         Operation::Update(admin_to_update.clone()),
    //         &provider,
    //         ciphersuite,
    //         &mut state,
    //         committer_name,
    //         "Admin_7".to_string(),
    //     )
    //     .unwrap();

    //     check_sync_sumac(&state);
    // }
}
