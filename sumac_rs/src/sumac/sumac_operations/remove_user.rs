use std::collections::HashMap;

use openmls::{
    prelude::{Ciphersuite, LeafNodeIndex},
    tree_sumac::{nodes::traits::OptionNode, OptionLeafNodeTMKA},
};
use openmls_traits::OpenMlsProvider;

use crate::{
    errors::SumacError,
    sumac::{
        create_large_sumac_group, process_broadcast_tmka,
        regeneration::{EncryptedRegenerationSet, RegenerationSet},
        SumacAdminGroup, SumacUserGroup,
    },
    test_utils::{check_sync_sumac, create_pool_of_users, setup_provider, CIPHERSUITE},
    tmka::CommitTMKABroadcast,
    user::User,
    Operation,
};

fn admins_process_regeneration_procedure_remove_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins_group: &mut HashMap<String, SumacAdminGroup>,
    regeneration_set: &RegenerationSet,
    username_committer: &String,
) -> Result<(), SumacError> {
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
        });

    Ok(())
}

pub fn remove_user_committer(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_to_remove: &String,
    username_committer: &String,
) -> Result<(CommitTMKABroadcast, EncryptedRegenerationSet, LeafNodeIndex), SumacError> {
    // We retreive the user we wish to remove to the group
    let user_to_remove = all_users.get(username_to_remove).unwrap();

    // We also retrieve the committer, and its group view
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();

    // The committer remove the target user in its own tree. It sends the broadcast commit to the users
    let (commit_broadcast_tmka, _) = group_committer.tmka_mut().commit(
        Operation::Remove(user_to_remove.clone()),
        ciphersuite,
        provider,
    )?;

    // The committer then generates the regeneration set
    let leaf_index_remove_user = commit_broadcast_tmka.target_leaf_index().clone();

    let regeneration_set = group_committer.tmka().build_regeneration_path(
        provider,
        ciphersuite,
        &leaf_index_remove_user,
        false,
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
        encrypted_regeneration_set,
        leaf_index_remove_user,
    ))
}

pub fn remove_user_other_admins(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_committer: &String,
    encrypted_regeneration_set: &EncryptedRegenerationSet,
    leaf_index_to_remove: &LeafNodeIndex,
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

    // blank the leaf
    for (_, admin_group) in all_admin_groups
        .iter_mut()
        .filter(|(admin_name, _)| *admin_name != username_committer)
    {
        let tree = admin_group.tmka_mut().tree.clone();
        let mut diff = tree.empty_diff();
        diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), *leaf_index_to_remove);
        admin_group
            .tmka_mut()
            .tree
            .merge_diff(diff.into_staged_diff().unwrap());
    }

    // absorb it in their own TMKA tree. They output their regenerated path (as well as their dumb ratchet tree to give the layout to the new user)
    admins_process_regeneration_procedure_remove_user(
        provider,
        ciphersuite,
        all_admin_groups,
        &regeneration_set,
        &committer.identity(),
    )?;

    Ok(())
}

pub fn remove_user_standard_users(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_committer: &String,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_removed_user: &LeafNodeIndex,
    username_removed_user: &String,
) -> Result<(), SumacError> {
    // The users process the broadcast. They add the new leaf to their view of the committer's tree
    process_broadcast_tmka(
        all_user_groups,
        &username_committer,
        commit_broadcast_tmka,
        provider,
        ciphersuite,
        Some(username_removed_user.to_string()),
    )?;

    //The standard users (but the updated one) do all the regeneration process by themselves.

    all_user_groups
        .iter_mut()
        .filter(|(username, _)| *username != username_removed_user)
        .for_each(|(_, group)| {
            //Chaque user peut dériver le regeneration set local
            let regeneration_set = group
                .forest
                .get(username_committer)
                .unwrap()
                .build_regeneration_path(provider, ciphersuite, leaf_index_removed_user, false);

            // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
            group
                .forest_mut()
                .iter_mut()
                .filter(|(id_admin, _)| *id_admin != username_committer)
                .for_each(|(_, tree)| {
                    let mut diff = tree.tree.empty_diff();
                    diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), *leaf_index_removed_user);
                    tree.tree.merge_diff(diff.into_staged_diff().unwrap());
                    tree.commit_secret =
                        tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
                });
        });

    // erase the state of the deleted user
    all_user_groups.remove(username_removed_user);

    Ok(())
}

pub fn full_remove_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_to_remove: String,
    username_committer: String,
) -> Result<(), SumacError> {
    //////Committer's View/////////
    let (commit_broadcast_tmka, encrypted_regeneration_set, leaf_index_to_remove) =
        remove_user_committer(
            provider,
            ciphersuite,
            all_users,
            all_admin_groups,
            &username_to_remove,
            &username_committer,
        )?;
    println!("committer ok");

    // //////////////////////////////////Other Admins' view////////////////////////////

    remove_user_other_admins(
        provider,
        ciphersuite,
        all_admins,
        all_admin_groups,
        &username_committer,
        &encrypted_regeneration_set,
        &leaf_index_to_remove,
    )?;
    println!("other admins ok");

    // ////////////////////////////Standard Users' view////////////////////////////////

    remove_user_standard_users(
        provider,
        ciphersuite,
        all_user_groups,
        &username_committer,
        commit_broadcast_tmka,
        &leaf_index_to_remove,
        &username_to_remove,
    )?;
    println!("standard users ok");

    Ok(())
}

#[test]
fn test_remove_user() {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
    let all_users = create_pool_of_users(10, &provider, "User".to_string());

    let (mut all_admins_groups, mut all_users_groups) =
        create_large_sumac_group(&provider, ciphersuite, &all_admins, &all_users).unwrap();

    full_remove_user(
        &provider,
        ciphersuite,
        &all_admins,
        &all_users,
        &mut all_admins_groups,
        &mut all_users_groups,
        "User_2".to_string(),
        "Admin_0".to_owned(),
    )
    .unwrap();

    check_sync_sumac(&all_admins_groups, &all_users_groups);
}

///////////////////For Benchmarks
///
pub fn remove_user_only_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_committer: &String,
    username_target_admin: &String,
    encrypted_regeneration_set: &EncryptedRegenerationSet,
    leaf_index_to_remove: &LeafNodeIndex,
) -> Result<(), SumacError> {
    let group_committer = all_admin_groups
        .get_mut(username_committer)
        .unwrap()
        .clone();
    let mut group_admin_target = all_admin_groups.get_mut(username_target_admin).unwrap();

    //The other admins get the regeneration set and decrypt it.
    let regeneration_set = encrypted_regeneration_set.decrypt_symmetric(
        provider.crypto(),
        ciphersuite,
        &group_committer
            .cgka()
            .derive_group_key(provider.crypto(), ciphersuite)?,
    );

    // blank the leaf
    let tree = group_admin_target.tmka_mut().tree.clone();
    let mut diff = tree.empty_diff();
    diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), *leaf_index_to_remove);
    group_admin_target
        .tmka_mut()
        .tree
        .merge_diff(diff.into_staged_diff().unwrap());

    // absorb it in their own TMKA tree. They output their regenerated path (as well as their dumb ratchet tree to give the layout to the new user)
    group_admin_target.tmka_mut().absorb_regeneration_path(
        provider,
        ciphersuite,
        &regeneration_set,
    );

    Ok(())
}

pub fn remove_user_only_one_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_committer: &String,
    commit_broadcast_tmka: &CommitTMKABroadcast,
    leaf_index_removed_user: &LeafNodeIndex,
    username_target_user: &String,
) -> Result<(), SumacError> {
    let mut user_group = all_user_groups.get_mut(username_target_user).unwrap();

    // The users process the broadcast. They add the new leaf to their view of the committer's tree

    user_group
        .forest_mut()
        .get_mut(username_committer)
        .unwrap()
        .process(&commit_broadcast_tmka, provider, ciphersuite)
        .unwrap();

    //The standard users (but the updated one) do all the regeneration process by themselves.

    let regeneration_set = user_group
        .forest
        .get(username_committer)
        .unwrap()
        .build_regeneration_path(provider, ciphersuite, leaf_index_removed_user, false);

    // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
    user_group
        .forest_mut()
        .iter_mut()
        .filter(|(id_admin, _)| *id_admin != username_committer)
        .for_each(|(_, tree)| {
            let mut diff = tree.tree.empty_diff();
            diff.just_replace_leaf(OptionLeafNodeTMKA::blank(), *leaf_index_removed_user);
            tree.tree.merge_diff(diff.into_staged_diff().unwrap());
            tree.commit_secret =
                tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
        });

    Ok(())
}
