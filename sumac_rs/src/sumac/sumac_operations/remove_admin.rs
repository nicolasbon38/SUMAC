use std::collections::HashMap;

use openmls::prelude::Secret as MlsSecret;
use openmls::{
    prelude::{Ciphersuite, Credential, HpkeCiphertext, OpenMlsCrypto, PathSecret},
    tree_sumac::{
        nodes::encryption_keys::{KeyPairRef, SymmetricKey},
        LeafNodeTMKA, ParentNodeTMKA,
    },
};
use openmls_traits::OpenMlsProvider;
use rand::{rng, seq::IteratorRandom};

use crate::sumac::create_large_sumac_group;
use crate::sumac::sumac_operations::add_admin::full_add_admin;
use crate::test_utils::create_pool_of_users;
use crate::{
    cgka::{CGKAGroup, CommitCGKABroadcast, CommitCGKAUnicast},
    crypto::{secret::Secret, types::AeadCiphertext},
    errors::SumacError,
    sumac::{
        process_broadcast_cgka,
        regeneration::{EncryptedRegenerationTree, RegenerationTree},
        setup_sumac,
        sumac_operations::add_user::full_add_user,
        SumacAdminGroup, SumacUserGroup,
    },
    test_utils::{check_sync_sumac, setup_provider, CIPHERSUITE},
    tmka::{admin_group::TmkaAdminGroup, user_group::TmkaSlaveGroup, TreeTMKA},
    user::User,
    Operation,
};

pub fn remove_admin_committer(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_removed_admin: &String,
    username_committer: &String,
) -> Result<(CommitCGKABroadcast, AeadCiphertext), SumacError> {
    let removed_admin = all_admins
        .get(username_removed_admin)
        .expect(&format!("{} not found", username_removed_admin));

    // We also retrieve the committer, and its group view
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();

    // The committer adds the new user in the admin tree. It sends the broadcast commit to the admins, and the (CGKA) welcome message of the admin tree to the new admin
    let (commit_broadcast_cgka, _) = group_committer.cgka_mut().commit(
        Operation::Remove(removed_admin.clone()),
        ciphersuite,
        provider,
    )?;
    //Derive the group key and updates it int he group
    let secret_group_key = group_committer
        .cgka()
        .commit_secret
        .derive_secret(provider.crypto(), ciphersuite)?;
    group_committer.sumac_group_key =
        SymmetricKey::derive_from_secret(provider.crypto(), ciphersuite, &secret_group_key.into())
            .map_err(|e| SumacError::MLSError(e))?;

    //retrieve the key of the committer's tree:
    let key_tree = group_committer.tmka().group_key.clone();

    // encrypt the group key to send it to
    let ciphertext = key_tree
        .encrypt(
            provider.crypto(),
            ciphersuite,
            group_committer.sumac_group_key.as_slice(),
        )
        .map_err(|e| SumacError::MLSError(e))?;

    Ok((commit_broadcast_cgka, ciphertext))
}

pub fn remove_admin_other_admins(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    commit_broadcast: CommitCGKABroadcast,
    username_committer: &String,
    username_removed_admin: &String
) -> Result<(), SumacError> {
    for (name, group) in all_admin_groups.iter_mut() {
        if (name != username_committer) && (name != username_removed_admin) {
            group
                .cgka_mut()
                .process(&commit_broadcast, provider, ciphersuite)?;
            group.sumac_group_key = group.cgka().group_key.clone();
        }
    }

    Ok(())
}

pub fn remove_admin_standard_users(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users_group: &mut HashMap<String, SumacUserGroup>,
    username_removed_admin: &String,
    username_committer: &String,
    encrypted_group_key: AeadCiphertext,
) -> Result<(), SumacError> {
    for (_, user_group) in all_users_group.iter_mut() {
        // delete the tree in the forest
        user_group.forest_mut().remove(username_removed_admin);

        //retrieves the key of the committer's tree
        let key = &user_group.forest.get(username_committer).unwrap().group_key;

        let new_secret_key = SymmetricKey::from_vec(
            key.decrypt(provider.crypto(), ciphersuite, &encrypted_group_key)
                .map_err(|e| SumacError::MLSError(e))?,
            ciphersuite,
        );

        user_group.sumac_group_key = new_secret_key;
    }
    Ok(())
}

pub fn full_remove_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_removed_admin: String,
    username_committer: String,
) -> Result<(), SumacError> {
    //////Committer's View/////////
    let (commit_broadcast_cgka, encrypted_new_key) = remove_admin_committer(
        provider,
        ciphersuite,
        all_admins,
        all_admin_groups,
        &username_removed_admin,
        &username_committer,
    )?;

    // //////////////////////////////////Other Admins' view////////////////////////////
    remove_admin_other_admins(
        provider,
        ciphersuite,
        all_admin_groups,
        commit_broadcast_cgka,
        &username_committer,
        &username_removed_admin
    )?;

        // remove the state of the target admin
    all_admin_groups.remove(&username_removed_admin);

    // ////////////////////////////Standard Users' view////////////////////////////////

    remove_admin_standard_users(
        provider,
        ciphersuite,
        all_user_groups,
        &username_removed_admin,
        &username_committer,
        encrypted_new_key,
    )?;

    Ok(())
}

#[test]
fn test_remove_admin() {
    let mut rng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let all_admins = create_pool_of_users(10, &provider, "Admin".to_string());
    let all_users = create_pool_of_users(10, &provider, "User".to_string());

    let (mut all_admins_groups, mut all_users_groups) =
        create_large_sumac_group(&provider, ciphersuite, &all_admins, &all_users).unwrap();

    let mut committer_name = "Admin_0".to_string();

    full_remove_admin(
        &provider,
        ciphersuite,
        &all_admins,
        &mut all_admins_groups,
        &mut all_users_groups,
        "Admin_7".to_string(),
        committer_name,
    )
    .unwrap();

    check_sync_sumac(&all_admins_groups, &all_users_groups);
}

/////////////////////:For benchmarks////////////////////

pub fn remove_admin_only_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    commit_broadcast: CommitCGKABroadcast,
    username_target_admin: &String,
) -> Result<(), SumacError> {
    let mut group = all_admin_groups.get_mut(username_target_admin).unwrap();
    group
        .cgka_mut()
        .process(&commit_broadcast, provider, ciphersuite)?;
    group.sumac_group_key = group.cgka().group_key.clone();
    Ok(())
}

pub fn remove_admin_only_one_standard_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    encrypted_group_key: AeadCiphertext,
    username_committer: &String,
    username_removed_admin: &String,
) -> Result<(), SumacError> {
    // delete the tree in the forest
    user_group.forest_mut().remove(username_removed_admin);

    //retrieves the key of the committer's tree
    let key = &user_group.forest.get(username_committer).unwrap().group_key;

    let new_secret_key = SymmetricKey::from_vec(
        key.decrypt(provider.crypto(), ciphersuite, &encrypted_group_key)
            .map_err(|e| SumacError::MLSError(e))?,
        ciphersuite,
    );

    user_group.sumac_group_key = new_secret_key;

    Ok(())
}
