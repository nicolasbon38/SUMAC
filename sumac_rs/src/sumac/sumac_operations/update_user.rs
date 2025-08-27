///////////////////////////////////////////////Add User//////////////////////////////////////////

use std::collections::HashMap;

use openmls::{
    prelude::{Ciphersuite, LeafNodeIndex},
    tree_sumac::{
        nodes::encryption_keys::{KeyPairRef, SymmetricKey},
        LeafNodeTMKA,
    },
};
use openmls_traits::OpenMlsProvider;

use crate::{
    crypto::{hpke::hpke_encrypt_secret, secret::Secret, types::AeadCiphertext},
    errors::SumacError,
    sumac::{
        create_large_sumac_group, process_broadcast_tmka,
        regeneration::{EncryptedRegenerationSet, EncryptedRegenerationSetHPKE, RegenerationSet},
        setup_sumac, SumacAdminGroup, SumacUserGroup,
    },
    test_utils::{check_sync_sumac, create_pool_of_users, setup_provider, CIPHERSUITE},
    tmka::{user_group::TmkaSlaveGroup, CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    user::User,
    Operation,
};

fn regeneration_procedure_update_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    admin_group: &mut SumacAdminGroup,
    all_users: &HashMap<String, User>,
    regeneration_set: &RegenerationSet,
    username_updated_user: &String,
) -> Result<(), SumacError> {
    let user_to_be_updated = all_users.get(username_updated_user).unwrap();

    let index: LeafNodeIndex = regeneration_set.leaf_index();
    admin_group
        .tmka_mut()
        .absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
    let leaf_secret = regeneration_set.leaf_secret().unwrap();
    //replace the placeholder by a new node containing this new secret.
    let new_leaf_node = LeafNodeTMKA::new(
        provider.crypto(),
        ciphersuite,
        user_to_be_updated.credential_with_key().credential.clone(),
        leaf_secret.clone().into(),
    )
    .expect("Impossible to create the new leaf node");

    admin_group.tmka_mut().replace_leaf(index, new_leaf_node);
    Ok(())
}

fn admins_process_regeneration_procedure_update_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins_group: &mut HashMap<String, SumacAdminGroup>,
    all_users: &HashMap<String, User>,
    regeneration_sets: &HashMap<String, RegenerationSet>,
    username_committer: &String,
    username_updated_user: &String,
) -> Result<(), SumacError> {
    all_admins_group
        .iter_mut()
        .filter(|(username, _)| *username != username_committer)
        .for_each(|(username, admin_group)| {
            let regeneration_set = regeneration_sets.get(username).unwrap();
            regeneration_procedure_update_user(
                provider,
                ciphersuite,
                admin_group,
                all_users,
                regeneration_set,
                username_updated_user,
            )
            .unwrap();
        });

    Ok(())
}

pub fn update_user_committer(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_to_update: &String,
    username_committer: &String,
) -> Result<
    (
        CommitTMKABroadcast,
        CommitTMKAUnicast,
        HashMap<String, EncryptedRegenerationSetHPKE>,
        LeafNodeIndex,
        AeadCiphertext,
    ),
    SumacError,
> {
    // We retreive the user we wish to add to the group
    let user_to_update = all_users.get(username_to_update).unwrap();

    // We also retrieve the committer, and its group view
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();

    // The committer adds the new user in its own tree. It sends the broadcast commit to the users, and the (TMKA) welcome message of its tree to the new user
    let (commit_broadcast_tmka, commit_unicast_tmka_admin) = group_committer.tmka_mut().commit(
        Operation::Update(user_to_update.clone()),
        ciphersuite,
        provider,
    )?;

    // derive a new secret and a new key to serve as the group key
    let group_key = group_committer.update_group_key_from_tree(provider, ciphersuite)?;
    // encrypt the group key under the admin key
    let admin_key = group_committer.admin_key();
    let encrypted_group_key = admin_key
        .encrypt(provider.crypto(), ciphersuite, group_key.as_slice())
        .map_err(|e| SumacError::MLSError(e))?;

    // The committer then generates the regeneration set
    let commit_unicast_tmka_admin = commit_unicast_tmka_admin.unwrap();

    let leaf_index_updated_user = commit_unicast_tmka_admin.own_leaf_index().clone();

    let mut regeneration_sets = HashMap::new();
    for (admin_name, admin) in all_admins.iter() {
        let dummy_regeneration_set = group_committer.tmka().build_regeneration_path(
            provider,
            ciphersuite,
            &leaf_index_updated_user,
            true,
        );

        // The committer encrypt the regeneration set under the CGKA key.
        let encrypted_regeneration_set = dummy_regeneration_set.encrypt_hpke(
            provider,
            ciphersuite,
            admin
                .encryption_keypair()
                .expect("THe key package has not been built")
                .as_tuple()
                .0,
        )?;

        regeneration_sets.insert(admin_name.to_string(), encrypted_regeneration_set);
    }

    Ok((
        commit_broadcast_tmka,
        commit_unicast_tmka_admin,
        regeneration_sets,
        leaf_index_updated_user,
        encrypted_group_key,
    ))
}

pub fn update_user_other_admins(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_to_update: &String,
    username_committer: &String,
    encrypted_group_key: &AeadCiphertext,
    encrypted_regeneration_sets: &HashMap<String, EncryptedRegenerationSetHPKE>,
) -> Result<(), SumacError> {
    let committer = all_admins.get(username_committer).unwrap();

    //The other admins get the regeneration set and decrypt it.
    let regeneration_sets = encrypted_regeneration_sets
        .iter()
        .map(|(admin_name, encrypted_regeneration_set)| {
            let regeneration_set = encrypted_regeneration_set
                .decrypt(
                    provider,
                    ciphersuite,
                    all_admins
                        .get(admin_name)
                        .unwrap()
                        .encryption_keypair()
                        .unwrap()
                        .as_tuple()
                        .1,
                )
                .unwrap();
            (admin_name.to_string(), regeneration_set)
        })
        .collect();

    // absorb it in their own TMKA tree. They output their regenerated path (as well as their dumb ratchet tree to give the layout to the new user)
    admins_process_regeneration_procedure_update_user(
        provider,
        ciphersuite,
        all_admin_groups,
        all_users,
        &regeneration_sets,
        &committer.identity(),
        &username_to_update,
    )?;

    //decrypt the group key
    for (_, admin_group) in all_admin_groups.iter_mut() {
        let admin_key = admin_group.admin_key();

        let group_key = SymmetricKey::from_vec(
            admin_key
                .decrypt(provider.crypto(), ciphersuite, encrypted_group_key)
                .map_err(|e| SumacError::MLSError(e))?,
            ciphersuite,
        );

        admin_group.sumac_group_key = group_key;
    }

    Ok(())
}

pub fn update_user_standard_users(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_committer: &String,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_updated_user: &LeafNodeIndex,
    username_updated_user: &String,
) -> Result<(), SumacError> {
    // The users process the broadcast. They add the new leaf to their view of the committer's tree
    process_broadcast_tmka(
        all_user_groups,
        &username_committer,
        commit_broadcast_tmka,
        provider,
        ciphersuite,
        Some(username_updated_user.to_string()),
    )?;

    //The standard users (but the updated one) do all the regeneration process by themselves.

    all_user_groups
        .iter_mut()
        .filter(|(username, _)| *username != username_updated_user)
        .for_each(|(_, group)| {
            //Chaque user peut dériver le regeneration set local
            let regeneration_set = group
                .forest
                .get(username_committer)
                .unwrap()
                .build_regeneration_path(provider, ciphersuite, leaf_index_updated_user, false);

            // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
            group
                .forest_mut()
                .iter_mut()
                .filter(|(id_admin, _)| *id_admin != username_committer)
                .for_each(|(_, tree)| {
                    tree.commit_secret =
                        tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
                });
        });

    // The standard users also updates their group key: rederive a secrt from the commit secret of the committer's tree.
    for (_, user_group) in all_user_groups.iter_mut() {
        user_group.update_group_key_from_tree(provider, ciphersuite, &username_committer)?;
    }

    Ok(())
}

pub fn update_user_target_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_committer: &String,
    commit_unicast_tmka_admin: CommitTMKAUnicast,
    leaf_index_updated_user: &LeafNodeIndex,
    usernrname_updated_user: &String,
) -> Result<(), SumacError> {
    let group_to_update = all_user_groups.get_mut(usernrname_updated_user).unwrap();

    group_to_update
        .forest_mut()
        .get_mut(username_committer)
        .unwrap()
        .process_self_update(commit_unicast_tmka_admin, provider, ciphersuite)?;

    // Derive the regeneration set
    let regeneration_set = group_to_update
        .forest_mut()
        .get_mut(username_committer)
        .unwrap()
        .build_regeneration_path(provider, ciphersuite, leaf_index_updated_user, true);

    // Apply the regeneration procedure in all of other trees
    for (_admin_name, tree) in group_to_update
        .forest_mut()
        .iter_mut()
        .filter(|(admin_name, _)| *admin_name != username_committer)
    {
        tree.commit_secret =
            tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
    }

    Ok(())
}

pub fn full_update_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_updated_user: String,
    username_committer: String,
) -> Result<(), SumacError> {
    //////Committer's View/////////
    let (
        commit_broadcast_tmka,
        commit_unicast_tmka_admin,
        encrypted_regeneration_sets,
        leaf_index_updated_user,
        encrypted_group_key,
    ) = update_user_committer(
        provider,
        ciphersuite,
        all_users,
        all_admins,
        all_admin_groups,
        &username_updated_user,
        &username_committer,
    )?;
    println!("committer ok");

    // //////////////////////////////////Other Admins' view////////////////////////////

    update_user_other_admins(
        provider,
        ciphersuite,
        all_admins,
        all_users,
        all_admin_groups,
        &username_updated_user,
        &username_committer,
        &encrypted_group_key,
        &encrypted_regeneration_sets,
    )?;
    println!("other admins ok");

    // ////////////////////////////Standard Users' view////////////////////////////////

    update_user_standard_users(
        provider,
        ciphersuite,
        all_user_groups,
        &username_committer,
        commit_broadcast_tmka,
        &leaf_index_updated_user,
        &username_updated_user,
    )?;
    println!("standard users ok");

    // /////////////////////////////New User's view////////////////////////////////////:

    update_user_target_user(
        provider,
        ciphersuite,
        all_user_groups,
        &username_committer,
        commit_unicast_tmka_admin,
        &leaf_index_updated_user,
        &username_updated_user,
    )?;
    println!("Updated user ok");

    Ok(())
}

#[test]
fn test_update_user() {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
    let all_users = create_pool_of_users(10, &provider, "User".to_string());

    let (mut all_admins_groups, mut all_users_groups) =
        create_large_sumac_group(&provider, ciphersuite, &all_admins, &all_users).unwrap();

    for (username, _) in all_users.iter() {
        full_update_user(
            &provider,
            ciphersuite,
            &all_admins,
            &all_users,
            &mut all_admins_groups,
            &mut all_users_groups,
            username.to_string(),
            "Admin_0".to_owned(),
        )
        .unwrap();

        check_sync_sumac(&all_admins_groups, &all_users_groups);
    }
}

// // /////////////////functions for benchmark$

pub fn update_user_only_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
    admin_group: &mut SumacAdminGroup,
    admin_name: &String,
    username_updated_user: &String,
    encrypted_group_key: &AeadCiphertext,
    encrypted_regeneration_set: &EncryptedRegenerationSetHPKE,
) -> Result<(), SumacError> {
    let regeneration_set = encrypted_regeneration_set
        .decrypt(
            provider,
            ciphersuite,
            all_admins
                .get(admin_name)
                .unwrap()
                .encryption_keypair()
                .unwrap()
                .as_tuple()
                .1,
        )
        .unwrap();

    regeneration_procedure_update_user(
        provider,
        ciphersuite,
        admin_group,
        all_users,
        &regeneration_set,
        username_updated_user,
    )?;

    let admin_key = admin_group.admin_key();

    let group_key = SymmetricKey::from_vec(
        admin_key
            .decrypt(provider.crypto(), ciphersuite, encrypted_group_key)
            .map_err(|e| SumacError::MLSError(e))?,
        ciphersuite,
    );

    admin_group.sumac_group_key = group_key;

    Ok(())
}

pub fn update_user_only_one_other_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    username_committer: &String,
    commit_broadcast_tmka: &CommitTMKABroadcast,
    leaf_index_updated_user: &LeafNodeIndex,
) -> Result<(), SumacError> {
    // The users process the broadcast. They add the new leaf to their view of the committer's tree
    user_group
        .forest_mut()
        .get_mut(username_committer)
        .unwrap()
        .process(commit_broadcast_tmka, provider, ciphersuite)?;

    //Chaque user peut dériver le regeneration set local
    let regeneration_set = user_group
        .forest
        .get(username_committer)
        .unwrap()
        .build_regeneration_path(provider, ciphersuite, leaf_index_updated_user, false);

    // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
    user_group
        .forest_mut()
        .iter_mut()
        .filter(|(id_admin, _)| *id_admin != username_committer)
        .for_each(|(_, tree)| {
            tree.commit_secret =
                tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
        });
    Ok(())
}
