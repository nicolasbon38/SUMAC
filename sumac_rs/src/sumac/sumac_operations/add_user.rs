///////////////////////////////////////////////Add User//////////////////////////////////////////

use std::collections::HashMap;

use openmls::{
    prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex, ParentNodeIndex},
    tree_sumac::{nodes::encryption_keys::KeyPairRef, LeafNodeTMKA, ParentNodeTMKA},
};
use openmls_traits::OpenMlsProvider;

use crate::{
    crypto::{
        hpke::{hpke_decrypt_secret, hpke_encrypt_secret},
        secret::Secret,
    },
    errors::SumacError,
    sumac::{
        process_broadcast_tmka,
        regeneration::{EncryptedCombinedPath, EncryptedRegenerationSet, RegenerationSet},
        setup_sumac, SumacAdminGroup, SumacUserGroup,
    },
    test_utils::{check_sync_sumac, setup_provider, CIPHERSUITE},
    tmka::{user_group::TmkaSlaveGroup, CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    user::User,
    Operation,
};


fn admins_process_regeneration_procedure_add_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins_group: &mut HashMap<String, SumacAdminGroup>,
    all_users: &HashMap<String, User>,
    regeneration_set: &RegenerationSet,
    username_committer: &String,
    username_new_user: &String,
) -> Result<
    HashMap<
        String,
        (
            TreeTMKA,
            HpkeCiphertext,
            EncryptedCombinedPath,
        ),
    >,
    SumacError,
> {
    let mut welcome_new_user_sumac = HashMap::new();

    let new_user = all_users.get(username_new_user).unwrap();

    all_admins_group
        .iter_mut()
        .filter(|(username, _)| *username != username_committer)
        .for_each(|(username, admin_group)| {
            let index: LeafNodeIndex = admin_group.tmka_mut().add_placeholder_leaf(ciphersuite); // useful so the layout of the path secret match
            assert_eq!(index, regeneration_set.leaf_index());
            let regenerated_secrets = admin_group.tmka_mut().absorb_regeneration_path(
                provider,
                ciphersuite,
                &regeneration_set,
            );
            // Now, add the actual leaf
            // sample a random leaf secret
            let leaf_secret = Secret::random(ciphersuite, provider.rand()).unwrap();

            //replace the placeholder by a new node containing this new secret.
            let new_leaf_node = LeafNodeTMKA::new(
                provider.crypto(),
                ciphersuite,
                new_user.credential_with_key().credential.clone(),
                leaf_secret.clone().into(),
            )
            .expect("Impossible to create the new leaf node");

            admin_group.tmka_mut().replace_leaf(index, new_leaf_node);

            // encrypt the leaf secret and the regenerated secrets under the public key of the new_usrer

            let encrypted_leaf_secret = hpke_encrypt_secret(
                provider,
                ciphersuite,
                &leaf_secret,
                new_user.encryption_keypair().unwrap().public_key(),
            ).unwrap();


            let encrypted_combined_path = regenerated_secrets
                .encrypt_hpke(
                    provider,
                    ciphersuite,
                    new_user.encryption_keypair().unwrap().public_key(),
                )
                .unwrap();

            let public_tree = admin_group.tmka().generate_white_tree(ciphersuite);

            welcome_new_user_sumac.insert(
                username.clone(),
                (
                    public_tree,
                    encrypted_leaf_secret,
                    encrypted_combined_path,
                ),
            );
        });

    Ok(welcome_new_user_sumac)
}


pub fn add_user_committer(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_new_user: &String,
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
    let new_user = all_users.get(username_new_user).unwrap();

    // We also retrieve the committer, and its group view
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();

    // The committer adds the new user in its own tree. It sends the broadcast commit to the users, and the (TMKA) welcome message of its tree to the new user
    let (commit_broadcast_tmka, commit_unicast_tmka_admin) = group_committer.tmka_mut().commit(
        Operation::Add(new_user.clone()),
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
        commit_unicast_tmka_admin,
        encrypted_regeneration_set,
        leaf_index_new_user,
    ))
}

pub fn add_user_other_admins(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_new_user: &String,
    username_committer: &String,
    encrypted_regeneration_set: &EncryptedRegenerationSet,
) -> Result<HashMap<String, (TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>, SumacError> {
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
    let welcome_new_user = admins_process_regeneration_procedure_add_user(
        provider,
        ciphersuite,
        all_admin_groups,
        all_users,
        &regeneration_set,
        &committer.identity(),
        &username_new_user,
    )?;

    Ok(welcome_new_user)
}

pub fn add_user_standard_users(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_committer: String,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_new_user: &LeafNodeIndex,
) -> Result<(), SumacError> {
    // The users process the broadcast. They add the new leaf to their view of the committer's tree
    process_broadcast_tmka(
        all_user_groups,
        &username_committer,
        commit_broadcast_tmka,
        provider,
        ciphersuite,
        None    // the group of the new user have not been created yet
    )?;

    //The standard users (but the new one) do all the regeneration process by themselves.

    all_user_groups.iter_mut().for_each(|(_, group)| {
        //Chaque user peut dériver le regeneration set local
        let regeneration_set = group
            .forest
            .get(&username_committer)
            .unwrap()
            .build_regeneration_path(provider, ciphersuite, leaf_index_new_user, false);

        // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
        group
            .forest_mut()
            .iter_mut()
            .filter(|(id_admin, _)| **id_admin != username_committer)
            .for_each(|(_, tree)| {
                // add placehomder leaf
                let new_leaf_index = tree.add_placeholder_leaf(ciphersuite);
                assert_eq!(new_leaf_index, *leaf_index_new_user);
                tree.commit_secret =
                    tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
            });
    });

    Ok(())
}

pub fn add_user_new_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    username_new_user: String,
    username_committer: String,
    commit_unicast_tmka_admin: CommitTMKAUnicast,
    welcome_new_user: HashMap<String, (TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>,
    leaf_index_new_user: &LeafNodeIndex,
) -> Result<SumacUserGroup, SumacError> {
    let new_user = all_users.get(&username_new_user).unwrap();

    // The new user process the welcome message. It now owns a view of the committer's tree that it puts into their forest.
    let group_new_user_for_committer = TmkaSlaveGroup::process_welcome(
        commit_unicast_tmka_admin,
        provider,
        ciphersuite,
        new_user,
    )?;

    let mut forest_new_user = HashMap::new();
    forest_new_user.insert(username_committer.clone(), group_new_user_for_committer);
    let mut new_user_group = SumacUserGroup {
        forest: forest_new_user,
    };

    // Then th new user process each message from the other admins
    for (admin_name, (mut public_tree, encrypted_leaf_secret, encrypted_combined_path)) in
        welcome_new_user.into_iter()
    {
        let mut diff = public_tree.empty_diff();

        // Start by decrypting the secret
        let leaf_secret = hpke_decrypt_secret(
            provider,
            ciphersuite,
            &encrypted_leaf_secret,
            new_user.encryption_keypair()?.private_key(),
        )?;

        diff.just_replace_leaf(
            LeafNodeTMKA::new(
                provider.crypto(),
                ciphersuite,
                new_user.credential_with_key().credential.clone(),
                leaf_secret.into(),
            )
            .map_err(|err| SumacError::MLSError(err))?
            .into(),
            *leaf_index_new_user,
        );

        // Decrypt the regenerated set
        let mut commit_secret = Secret::zero(ciphersuite);

        let keypair = new_user.encryption_keypair()?;
        let decryption_key = keypair.private_key();

        let (indexes, path_secrets) =
            encrypted_combined_path.decrypt(provider, ciphersuite, decryption_key)?;

        let len = indexes.len();

        for (i, (index, path_secret)) in indexes.iter().zip(path_secrets).enumerate() {
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

        let user_tree = TmkaSlaveGroup {
            tree: public_tree,
            own_leaf_index: *leaf_index_new_user,
            user: new_user.clone(),
            commit_secret,
        };

        new_user_group.forest_mut().insert(admin_name, user_tree);
    }
    Ok(new_user_group)
}

pub fn full_add_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_new_user: String,
    username_committer: String,
) -> Result<(), SumacError> {
    //////Committer's View/////////
    let (
        commit_broadcast_tmka,
        commit_unicast_tmka_admin,
        encrypted_regeneration_set,
        leaf_index_new_user,
    ) = add_user_committer(
        provider,
        ciphersuite,
        all_users,
        all_admin_groups,
        &username_new_user,
        &username_committer,
    )?;
    println!("committer ok");

    // //////////////////////////////////Other Admins' view////////////////////////////

    let welcome_new_user = add_user_other_admins(
        provider,
        ciphersuite,
        all_admins,
        all_users,
        all_admin_groups,
        &username_new_user,
        &username_committer,
        &encrypted_regeneration_set,
    )?;
    println!("other admins ok");

    // ////////////////////////////Standard Users' view////////////////////////////////

    add_user_standard_users(
        provider,
        ciphersuite,
        all_user_groups,
        username_committer.clone(),
        commit_broadcast_tmka,
        &leaf_index_new_user,
    )?;
    println!("standard users ok");

    // /////////////////////////////New User's view////////////////////////////////////:

    let new_user_group = add_user_new_user(
        provider,
        ciphersuite,
        all_users,
        username_new_user.clone(),
        username_committer,
        commit_unicast_tmka_admin,
        welcome_new_user,
        &leaf_index_new_user,
    )?;
    println!("new user ok");

    all_user_groups.insert(username_new_user, new_user_group);

    Ok(())
}

#[test]
fn test_add_user() {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let (mut all_admins, mut all_users, mut all_admins_groups, mut all_users_groups) =
        setup_sumac(&provider, ciphersuite, 10, 10).unwrap();

    assert_eq!(all_users_groups.len(), 1);

    for (username, _) in all_users.iter() {
        if username == "User_0" {
            continue;
        }
        full_add_user(
            &provider,
            ciphersuite,
            &mut all_admins,
            &all_users,
            &mut all_admins_groups,
            &mut all_users_groups,
            username.to_string(),
            "Admin_0".to_owned(),
        )
        .unwrap();

        check_sync_sumac(&all_admins_groups, &all_users_groups);
    }

    assert_eq!(all_admins_groups.len(), 1);
    assert_eq!(all_users_groups.len(), all_users.len());
}

/////////////////functions for benchmark$

pub fn add_user_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users: &HashMap<String, User>,
    admin_group: &mut SumacAdminGroup,
    new_user: &User,
    committer: &User,
    encrypted_regeneration_set: &EncryptedRegenerationSet,
) -> Result<(), SumacError> {
    //The other admins get the regeneration set and decrypt it.
    let regeneration_set = encrypted_regeneration_set.decrypt_symmetric(
        provider.crypto(),
        ciphersuite,
        &admin_group
            .cgka()
            .derive_group_key(provider.crypto(), ciphersuite)?,
    );

    let index = admin_group.tmka_mut().add_placeholder_leaf(ciphersuite); // useful so the layout of the path secret match
    assert_eq!(index, regeneration_set.leaf_index());
    let regenerated_secrets =
        admin_group
            .tmka_mut()
            .absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
    // Now, add the actual leaf
    // sample a random leaf secret
    let leaf_secret = Secret::random(ciphersuite, provider.rand()).unwrap();

    //replace the placeholder by a new node containing this new secret.
    let new_leaf_node = LeafNodeTMKA::new(
        provider.crypto(),
        ciphersuite,
        new_user.credential_with_key().credential.clone(),
        leaf_secret.clone().into(),
    )
    .expect("Impossible to create the new leaf node");

    admin_group.tmka_mut().replace_leaf(index, new_leaf_node);

    // encrypt the leaf secret and the regenerated secrets under the public key of the new_usrer

    let _encrypted_leaf_secret = hpke_encrypt_secret(
        provider,
        ciphersuite,
        &leaf_secret,
        new_user.encryption_keypair().unwrap().public_key(),
    )
    .unwrap();

    let _encrypted_regenerated_secrets = regenerated_secrets
        .encrypt_hpke(
            provider,
            ciphersuite,
            new_user.encryption_keypair().unwrap().public_key(),
        )
        .unwrap();

    let _public_tree = admin_group.tmka().generate_white_tree(ciphersuite);

    Ok(())
}

pub fn add_user_one_standard_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    username_committer: String,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_new_user: &LeafNodeIndex,
) -> Result<(), SumacError> {
    // The users process the broadcast. They add the new leaf to their view of the committer's tree
    user_group
        .forest
        .get_mut(&username_committer)
        .unwrap()
        .process(&commit_broadcast_tmka, provider, ciphersuite)?;

    //Chaque user peut dériver le regeneration set local
    let regeneration_set = user_group
        .forest
        .get(&username_committer)
        .unwrap()
        .build_regeneration_path(provider, ciphersuite, leaf_index_new_user, false);

    // il peut ensuite le processer, dans chaque autre arbre de sa forêt (sauf celui du committer)
    user_group
        .forest_mut()
        .iter_mut()
        .filter(|(id_admin, _)| **id_admin != username_committer)
        .for_each(|(_, tree)| {
            // add placehomder leaf
            let new_leaf_index = tree.add_placeholder_leaf(ciphersuite);
            assert_eq!(new_leaf_index, *leaf_index_new_user);
            tree.commit_secret =
                tree.absorb_regeneration_path(provider, ciphersuite, &regeneration_set);
        });

    Ok(())
}
