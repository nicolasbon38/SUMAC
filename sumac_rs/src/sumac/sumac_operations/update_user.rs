///////////////////////////////////////////////Add User//////////////////////////////////////////

use std::collections::HashMap;

use openmls::{
    prelude::{Ciphersuite, LeafNodeIndex},
    tree_sumac::{nodes::encryption_keys::KeyPairRef, LeafNodeTMKA},
};
use openmls_traits::OpenMlsProvider;

use crate::{
    crypto::{hpke::hpke_encrypt_secret, secret::Secret},
    errors::SumacError,
    sumac::{
        create_large_sumac_group, process_broadcast_tmka,
        regeneration::{EncryptedRegenerationSet, RegenerationSet},
        setup_sumac, SumacAdminGroup, SumacUserGroup,
    },
    test_utils::{check_sync_sumac, create_pool_of_users, setup_provider, CIPHERSUITE},
    tmka::{user_group::TmkaSlaveGroup, CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    user::User,
    Operation,
};

fn admins_process_regeneration_procedure_update_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins_group: &mut HashMap<String, SumacAdminGroup>,
    all_users: &HashMap<String, User>,
    regeneration_set: &RegenerationSet,
    username_committer: &String,
    username_updated_user: &String,
) -> Result<(), SumacError> {
    let user_to_be_updated = all_users.get(username_updated_user).unwrap();

    all_admins_group
        .iter_mut()
        .filter(|(username, _)| *username != username_committer)
        .for_each(|(_, admin_group)| {
            let index: LeafNodeIndex = regeneration_set.leaf_index();
            let _ = admin_group.tmka_mut().absorb_regeneration_path(
                provider,
                ciphersuite,
                &regeneration_set,
            );

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
        });

    Ok(())
}

pub fn update_user_committer(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_to_update: &String,
    username_committer: &String,
) -> Result<
    (
        CommitTMKABroadcast,
        CommitTMKAUnicast,
        EncryptedRegenerationSet,
        LeafNodeIndex,
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

    // The committer then generates the regeneration set
    let commit_unicast_tmka_admin = commit_unicast_tmka_admin.unwrap();
    let leaf_index_new_user = commit_unicast_tmka_admin.own_leaf_index().clone();

    let regeneration_set = group_committer.tmka().build_regeneration_path(
        provider,
        ciphersuite,
        &leaf_index_new_user,
        true,
    );

    // The committer encrypt the regeneration set under the CGKA key.
    let encrypted_regeneration_set = regeneration_set.encrypt_symmetric(
        provider.crypto(),
        ciphersuite,
        &group_committer
            .cgka()
            .derive_group_key(provider.crypto(), ciphersuite)?,
    );

    Ok((
        commit_broadcast_tmka,
        commit_unicast_tmka_admin,
        encrypted_regeneration_set,
        leaf_index_new_user,
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
    encrypted_regeneration_set: &EncryptedRegenerationSet,
) -> Result<(), SumacError> {
    let committer = all_admins.get(username_committer).unwrap();
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();

    //The other admins get the regeneration set and decrypt it.
    let regeneration_set = encrypted_regeneration_set.decrypt_symmetric(
        provider.crypto(),
        ciphersuite,
        &group_committer
            .cgka()
            .derive_group_key(provider.crypto(), ciphersuite)?,
    );

    // absorb it in their own TMKA tree. They output their regenerated path (as well as their dumb ratchet tree to give the layout to the new user)
    admins_process_regeneration_procedure_update_user(
        provider,
        ciphersuite,
        all_admin_groups,
        all_users,
        &regeneration_set,
        &committer.identity(),
        &username_to_update,
    )?;

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
        encrypted_regeneration_set,
        leaf_index_updated_user,
    ) = update_user_committer(
        provider,
        ciphersuite,
        all_users,
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
        &encrypted_regeneration_set,
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

// /////////////////functions for benchmark$

pub fn update_user_only_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_to_update: &String,
    username_committer: &String,
    username_processing_admin: &String,
    encrypted_regeneration_set: &EncryptedRegenerationSet,
) -> Result<(), SumacError> {
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();
    //The other admins get the regeneration set and decrypt it.
    let regeneration_set = encrypted_regeneration_set.decrypt_symmetric(
        provider.crypto(),
        ciphersuite,
        &group_committer
            .cgka()
            .derive_group_key(provider.crypto(), ciphersuite)?,
    );

    let user_to_be_updated = all_users.get(username_to_update).unwrap();
    let admin_group = all_admin_groups.get_mut(username_processing_admin).unwrap();

    let index: LeafNodeIndex = regeneration_set.leaf_index();
    let _ =
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

pub fn update_user_only_one_other_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    username_committer: &String,
    commit_broadcast_tmka: &CommitTMKABroadcast,
    leaf_index_updated_user: &LeafNodeIndex,
) -> Result<(), SumacError> {
  // The users process the broadcast. They add the new leaf to their view of the committer's tree
    user_group.forest_mut().get_mut(username_committer).unwrap().process(commit_broadcast_tmka, provider, ciphersuite)?;


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
