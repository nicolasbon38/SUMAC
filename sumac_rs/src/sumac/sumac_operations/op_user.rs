use std::{collections::HashMap};

use openmls::{
    prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex},
    storage::OpenMlsProvider,
    tree_sumac::{
        nodes::{
            encryption_keys::{KeyPairRef, SymmetricKey},
            traits::OptionNode,
        },
        LeafNodeTMKA, OptionLeafNodeTMKA, ParentNodeTMKA,
    },
};

use crate::{
    crypto::{
        hpke::{hpke_decrypt_secret, hpke_encrypt_secret},
        secret::Secret,
        types::AeadCiphertext,
    },
    errors::SumacError,
    sumac::{
        regeneration::{EncryptedCombinedPath, EncryptedRegenerationSetHPKE, RegenerationSet},
        SumacAdminGroup, SumacState, SumacUserGroup,
    },
    tmka::{user_group::TmkaSlaveGroup, CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    user::User,
    Operation,
};

pub type Admin = User;
pub type AdminName = String;
pub type UserName = String;
pub type WelcomeNewUser = HashMap<AdminName, (TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>;

pub fn op_user_committer(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: &AdminName,
) -> Result<
    (
        CommitTMKABroadcast,
        Option<CommitTMKAUnicast>,
        HashMap<String, EncryptedRegenerationSetHPKE>,
        LeafNodeIndex,
        AeadCiphertext,
    ),
    SumacError,
> {
    //Collect names of other admins first (immutable borrow only)
    let admin_names: Vec<String> = state
        .all_admins
        .keys()
        .filter(|name| *name != username_committer)
        .cloned()
        .collect();

    let group_committer = state
        .all_admin_groups
        .get_mut(username_committer)
        .expect("The committter has no group");

    // The committter commits in its own TMKA
    let (commit_broadcast_tmka, commit_unicast_tmka_admin) =
        group_committer
            .tmka_mut()
            .commit(op.clone(), ciphersuite, provider)?;

    // derive a new secret and a new key to serve as the group key
    let group_key = group_committer.update_group_key_from_tree(provider, ciphersuite)?;

    // encrypt the group key under the admin key
    let admin_key = group_committer.admin_key();
    let encrypted_group_key =
        admin_key.encrypt(provider.crypto(), group_key.as_slice())?;

    // The committer then generates the regeneration sets
    let leaf_index_target_user = commit_broadcast_tmka.target_leaf_index().clone();

    let mut regeneration_sets = HashMap::new();

    for admin_name in admin_names {
        if admin_name == *username_committer {
            continue;
        }
        let dummy_regeneration_set = group_committer.tmka().build_regeneration_path(
            provider,
            ciphersuite,
            &leaf_index_target_user,
            matches!(op, Operation::Update(_)),
        );

        // The committer encrypt the regeneration set under the CGKA key.
        let encryption_keypair = state
            .all_admins
            .get(&admin_name)
            .expect("The target admin does not exist")
            .encryption_keypair()
            .expect("THe key package has not been built");

        let encrypted_regeneration_set = dummy_regeneration_set.encrypt_hpke(
            provider,
            ciphersuite,
            encryption_keypair.as_tuple().0,
        )?;

        regeneration_sets.insert(admin_name.to_string(), encrypted_regeneration_set);
    }

    Ok((
        commit_broadcast_tmka,
        commit_unicast_tmka_admin,
        regeneration_sets,
        leaf_index_target_user,
        encrypted_group_key,
    ))
}

pub fn op_user_other_admins(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: &AdminName,
    encrypted_group_key: AeadCiphertext,
    encrypted_regeneration_sets: &HashMap<String, EncryptedRegenerationSetHPKE>,
) -> Result<Option<WelcomeNewUser>, SumacError> {
    let mut welcome_new_user = match op {
        Operation::Add(_) => Some(HashMap::new()),
        _ => None,
    };
    for (admin_name, admin_group) in state
        .all_admin_groups
        .iter_mut()
        .filter(|(name, _)| *name != username_committer)
    {
        let regen = encrypted_regeneration_sets.get(admin_name).expect(&format!(
            "Missing Regeneration set for Admin {}",
            admin_name
        ));

        let current_admin = state
            .all_admins
            .get(admin_name)
            .expect("The current admin does not exists");

        let welcome_admin = op_user_one_other_admin(
            op,
            provider,
            ciphersuite,
            current_admin,
            admin_group,
            encrypted_group_key.clone(),
            regen,
        )?;
        if let Some(actual_welcome) = welcome_new_user.as_mut() {
            if let Some(wa) = welcome_admin {
                actual_welcome.insert(admin_name.to_string(), wa);
            } else {
                return Err(SumacError::TrueSumacError(
                    "No Combined Path has been produced, yet it seems that it is an Add-User"
                        .to_owned(),
                ));
            }
        }
    }

    Ok(welcome_new_user)
}

pub fn op_user_one_other_admin(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    current_admin: &Admin,
    admin_group: &mut SumacAdminGroup,
    encrypted_group_key: AeadCiphertext,
    encrypted_regeneration_set: &EncryptedRegenerationSetHPKE,
) -> Result<Option<(TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>, SumacError> {
    // Decrypt the regeneration set
    let keypair = current_admin
        .encryption_keypair()
        .expect("The KeyPackage has not been built");
    let regeneration_set =
        encrypted_regeneration_set.decrypt(provider, ciphersuite, keypair.as_tuple().1)?;

    // absorb it in its own TMKA tree. If it is an add, they output the combined path (as well as their dumb ratchet tree to give the layout to the new user)
    let welcome = admin_process_regeneration_procedure_op_user(
        op,
        provider,
        ciphersuite,
        admin_group,
        regeneration_set,
    )?;

    // decrypts the group key and updates it
    let admin_key = admin_group.admin_key();

    let group_key = SymmetricKey::from_vec(
        admin_key
            .decrypt(provider.crypto(), &encrypted_group_key)?,
        ciphersuite,
    );

    admin_group.sumac_group_key = group_key;
    Ok(welcome)
}

// Gros morceau

pub fn admin_process_regeneration_procedure_op_user(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    admin_group: &mut SumacAdminGroup,
    regeneration_set: RegenerationSet,
) -> Result<Option<(TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>, SumacError> {
    let index_new_leaf = match op {
        Operation::Add(_) => Some(admin_group.tmka_mut().add_placeholder_leaf(ciphersuite)), // useful so the layout of the path secret match
        _ => None,
    };

    let combined_path = admin_group.tmka_mut().absorb_regeneration_path(
        provider,
        ciphersuite,
        &regeneration_set,
        matches!(op, Operation::Update(_)),
    );

    let welcome = match op {
        Operation::Add(user) => {
            // We add the actual leaf (for now, it was just a placeholder)
            let leaf_secret = Secret::random(ciphersuite, provider.rand()).unwrap();

            //replace the placeholder by a new node containing this new secret.
            let new_leaf_node = LeafNodeTMKA::new(
                provider.crypto(),
                ciphersuite,
                user.credential_with_key().credential.clone(),
                leaf_secret.clone().into(),
            )
            .expect("Impossible to create the new leaf node");

            admin_group.tmka_mut().replace_leaf(
                index_new_leaf.expect("This index is supposed to exist"),
                new_leaf_node,
            );

            // encrypt the leaf secret and the regenerated secrets under the public key of the new_usrer
            let encrypted_leaf_secret = hpke_encrypt_secret(
                provider,
                ciphersuite,
                &leaf_secret,
                user.encryption_keypair().unwrap().public_key(),
            )
            .unwrap();

            let encrypted_combined_path = combined_path
                .encrypt_hpke(
                    provider,
                    ciphersuite,
                    user.encryption_keypair().unwrap().public_key(),
                )
                .unwrap();

            let public_tree = admin_group.tmka().generate_white_tree(ciphersuite);

            Some((public_tree, encrypted_leaf_secret, encrypted_combined_path))
        }
        _ => None,
    };

    Ok(welcome)
}

pub fn op_user_standard_users(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: &AdminName,
    username_target_user: &UserName,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_target_user: &LeafNodeIndex,
) -> Result<(), SumacError> {
    for (_, user_group) in state
        .all_user_groups
        .iter_mut()
        .filter(|(name, _)| *name != username_target_user)
    {
        op_user_one_standard_user(
            op,
            provider,
            ciphersuite,
            user_group,
            username_committer,
            commit_broadcast_tmka.clone(),
            leaf_index_target_user,
        )?
    }
    Ok(())
}

pub fn op_user_one_standard_user(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    username_committer: &AdminName,
    commit_broadcast: CommitTMKABroadcast,
    leaf_index_target_user: &LeafNodeIndex,
) -> Result<(), SumacError> {
    // Process the broadcast in the committer's tree
    user_group
        .forest_mut()
        .get_mut(username_committer)
        .expect("No committer in the forest")
        .process(&commit_broadcast, provider, ciphersuite)?;

    //Chaque user peut dériver le regeneration set local
    let regeneration_set = user_group
        .forest
        .get(username_committer)
        .unwrap()
        .build_regeneration_path(provider, ciphersuite, leaf_index_target_user, false);

    // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
    user_group
        .forest_mut()
        .iter_mut()
        .filter(|(id_admin, _)| *id_admin != username_committer)
        .for_each(|(_, tree)| {
            match op {
                Operation::Add(_) => {
                    let new_leaf_index = tree.add_placeholder_leaf(ciphersuite);
                    assert_eq!(new_leaf_index, *leaf_index_target_user);
                }
                Operation::Remove(_) => {
                    let mut diff = tree.tree.empty_diff();
                    diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), *leaf_index_target_user);
                    tree.tree.merge_diff(diff.into_staged_diff().unwrap());
                }
                Operation::Update(_) => {}
            }

            tree.commit_secret =
                tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
        });

    // The standard users also updates their group key: rederive a secrt from the commit secret of the committer's tree.
    user_group.update_group_key_from_tree(provider, ciphersuite, &username_committer)?;

    Ok(())
}

pub fn op_user_target_user(
    op: &Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: &AdminName,
    username_target_user: &UserName,
    commit_unicast_tmka_admin: Option<CommitTMKAUnicast>,
    welcome_new_user: Option<WelcomeNewUser>,
    leaf_index_target_user: &LeafNodeIndex,
) -> Result<Option<SumacUserGroup>, SumacError> {
    let result = match op {
        Operation::Add(user) => {
            // The new user process the welcome message. It now owns a view of the committer's tree that it puts into their forest.
            let group_new_user_for_committer = TmkaSlaveGroup::process_welcome(
                commit_unicast_tmka_admin.expect("For an Add, there should be a commit unicast"),
                provider,
                ciphersuite,
                user,
            )?;

            let mut forest_new_user = HashMap::new();
            forest_new_user.insert(username_committer.clone(), group_new_user_for_committer);
            let mut new_user_group = SumacUserGroup {
                forest: forest_new_user,
                sumac_group_key: SymmetricKey::zero(ciphersuite),
            };
            // derive the new group key
            new_user_group.update_group_key_from_tree(
                provider,
                ciphersuite,
                &username_committer,
            )?;

            // Then the new user process each message from the other admins
            for (admin_name, current_welcome) in welcome_new_user
                .expect("There should be a welcome because this is an Add")
                .into_iter()
            {
                let (mut public_tree, encrypted_leaf_secret, encrypted_combined_path) =
                    current_welcome;

                let mut diff = public_tree.empty_diff();

                // Start by decrypting the secret
                let leaf_secret = hpke_decrypt_secret(
                    provider,
                    ciphersuite,
                    &encrypted_leaf_secret,
                    user.encryption_keypair()?.private_key(),
                )?;

                diff.just_replace_leaf(
                    LeafNodeTMKA::new(
                        provider.crypto(),
                        ciphersuite,
                        user.credential_with_key().credential.clone(),
                        leaf_secret.into(),
                    )
                    .map_err(|err| SumacError::MLSError(err))?
                    .into(),
                    *leaf_index_target_user,
                );

                // Decrypt the regenerated set
                let mut commit_secret = Secret::zero(ciphersuite);

                let keypair = user.encryption_keypair()?;
                let decryption_key = keypair.private_key();

                let combined_path =
                    encrypted_combined_path.decrypt(provider, ciphersuite, decryption_key)?;

                let len = combined_path.secrets().len();
                assert!(combined_path.leaf_secret().is_none());

                for (i, (index, path_secret)) in combined_path.secrets().iter().enumerate() {
                    let new_parent_node = ParentNodeTMKA::new_from_path_secret(
                        provider.crypto(),
                        ciphersuite,
                        path_secret.clone(),
                        None,
                    )
                    .map_err(|err| SumacError::MLSError(err))?;

                    diff.just_replace_parent(new_parent_node.into(), *index);

                    if i == len - 1 {
                        commit_secret = path_secret
                            .derive_path_secret(provider.crypto(), ciphersuite)
                            .map_err(|err| SumacError::MLSError(err))?
                            .secret()
                            .into();
                    }
                }

                public_tree.merge_diff(diff.into_staged_diff().expect("Failed to stage the diff"));
                let group_key = SymmetricKey::derive_from_secret(
                    provider.crypto(),
                    ciphersuite,
                    &commit_secret.clone().into(),
                )
                .map_err(|e| SumacError::MLSError(e))?;

                let user_tree = TmkaSlaveGroup {
                    tree: public_tree,
                    own_leaf_index: *leaf_index_target_user,
                    user: user.clone(),
                    commit_secret,
                    group_key,
                };

                new_user_group.forest_mut().insert(admin_name, user_tree);
            }
            Some(new_user_group)
        }
        Operation::Update(_) => {
            let group_to_update = state
                .all_user_groups
                .get_mut(username_target_user)
                .expect("This group is supposed to already exist, as we are updating it");

            group_to_update
                .forest_mut()
                .get_mut(username_committer)
                .unwrap()
                .process_self_update(
                    commit_unicast_tmka_admin
                        .expect("An update is supposed to have generated a commit unicast"),
                    provider,
                    ciphersuite,
                )?;

            // Derive the regeneration set
            let regeneration_set = group_to_update
                .forest_mut()
                .get_mut(username_committer)
                .unwrap()
                .build_regeneration_path(provider, ciphersuite, leaf_index_target_user, true);

            // Apply the regeneration procedure in all of other trees
            for (_admin_name, tree) in group_to_update
                .forest_mut()
                .iter_mut()
                .filter(|(admin_name, _)| *admin_name != username_committer)
            {
                tree.commit_secret =
                    tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
            }

            None
        }
        Operation::Remove(_) => None,
    };

    Ok(result)
}

pub fn full_op_user(
    op: Operation,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    state: &mut SumacState,
    username_committer: AdminName,
    username_target_user: UserName,
) -> Result<(), SumacError> {
    //////Committer's View/////////
    let (
        commit_broadcast_tmka,
        commit_unicast_tmka_admin,
        encrypted_regeneration_sets,
        leaf_index_target_user,
        encrypted_group_key,
    ) = op_user_committer(&op, provider, ciphersuite, state, &username_committer)?;
    println!("committer ok");

    // //////////////////////////////////Other Admins' view////////////////////////////

    let welcome_new_user = op_user_other_admins(
        &op,
        provider,
        ciphersuite,
        state,
        &username_committer,
        encrypted_group_key,
        &encrypted_regeneration_sets,
    )?;
    println!("other admins ok");

    // ////////////////////////////Standard Users' view////////////////////////////////

    op_user_standard_users(
        &op,
        provider,
        ciphersuite,
        state,
        &username_committer,
        &username_target_user,
        commit_broadcast_tmka,
        &leaf_index_target_user,
    )?;
    println!("standard users ok");

    if matches!(op, Operation::Remove(_)) {
        // erase the state of the deleted user
        state.all_user_groups.remove(&username_target_user);
    }

    // /////////////////////////////New User's view////////////////////////////////////:

    let new_user_group = op_user_target_user(
        &op,
        provider,
        ciphersuite,
        state,
        &username_committer,
        &username_target_user,
        commit_unicast_tmka_admin,
        welcome_new_user,
        &leaf_index_target_user,
    )?;
    println!("new user ok");

    // Update the state
    match op {
        Operation::Add(_) => {
            assert!(new_user_group.is_some());
            state
                .all_user_groups
                .insert(username_target_user.to_string(), new_user_group.unwrap());
        }
        Operation::Remove(_) => {
            state.all_user_groups.remove(&username_target_user);
        }
        Operation::Update(_) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        sumac::{create_large_sumac_group, sumac_operations::op_user::full_op_user},
        test_utils::{check_sync_sumac, create_pool_of_users, create_user, setup_provider, CIPHERSUITE},
        Operation,
    };

    #[test]
    fn test_add_user() {
        let provider = setup_provider();
        let ciphersuite = CIPHERSUITE;

        let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
        let all_users = create_pool_of_users(10, &provider, "User".to_string());

        let mut state =
            create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();

        let username_to_add = "User_10".to_string();
        let user_to_add = create_user(username_to_add.to_string(), &provider);
        state.all_users.insert(username_to_add, user_to_add.clone());

        full_op_user(
            Operation::Add(user_to_add),
            &provider,
            ciphersuite,
            &mut state,
            "Admin_0".to_string(),
            "User_10".to_string(),
        )
        .unwrap();

        check_sync_sumac(&state);
    }


    #[test]
    fn test_remove_user() {
        let provider = setup_provider();
        let ciphersuite = CIPHERSUITE;

        let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
        let all_users = create_pool_of_users(10, &provider, "User".to_string());

        let mut state =
            create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();
        let user_to_remove = state.all_users.get("User_2").unwrap();

        full_op_user(
            Operation::Remove(user_to_remove.clone()),
            &provider,
            ciphersuite,
            &mut state,
            "Admin_0".to_string(),
            "User_2".to_string(),
        )
        .unwrap();

        check_sync_sumac(&state);
    }

    #[test]
    fn test_update_user() {
        let provider = setup_provider();
        let ciphersuite = CIPHERSUITE;

        let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
        let all_users = create_pool_of_users(10, &provider, "User".to_string());

        let mut state =
            create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();

        for (username_target_user, user) in state.all_users.clone().into_iter() {
            full_op_user(
                Operation::Update(user.clone()),
                &provider,
                ciphersuite,
                &mut state,
                "Admin_0".to_string(),
                username_target_user.to_string(),
            )
            .unwrap();

            check_sync_sumac(&state);
        }
    }
}
