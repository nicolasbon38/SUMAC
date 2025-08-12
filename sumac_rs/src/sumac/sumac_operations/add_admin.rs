use std::collections::HashMap;

use openmls::{prelude::{Ciphersuite, Credential, HpkeCiphertext}, tree_sumac::{nodes::encryption_keys::KeyPairRef, LeafNodeTMKA, ParentNodeTMKA}};
use openmls_traits::OpenMlsProvider;
use openmls::prelude::Secret as MlsSecret;
use rand::{rng, seq::IteratorRandom};

use crate::{
    cgka::{CGKAGroup, CommitCGKABroadcast, CommitCGKAUnicast}, crypto::secret::Secret, errors::SumacError, sumac::{process_broadcast_cgka, regeneration::{EncryptedRegenerationTree, RegenerationTree}, setup_sumac, sumac_operations::add_user::full_add_user, SumacAdminGroup, SumacUserGroup}, test_utils::{check_sync_sumac, setup_provider, CIPHERSUITE}, tmka::{admin_group::TmkaAdminGroup, user_group::TmkaSlaveGroup, TreeTMKA}, user::User, Operation
};

pub fn add_admin_committer(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    username_new_admin: &String,
    username_committer: &String,
) -> Result<(CommitCGKABroadcast, CommitCGKAUnicast, EncryptedRegenerationTree), SumacError> {
    let new_admin = all_admins.get(username_new_admin).expect(&format!("{} not found", username_new_admin));

    // We also retrieve the committer, and its group view
    let group_committer = all_admin_groups.get_mut(username_committer).unwrap();

    // The committer adds the new user in the admin tree. It sends the broadcast commit to the admins, and the (CGKA) welcome message of the admin tree to the new admin
    let (commit_broadcast_cgka, commit_unicast_cgka) = group_committer.cgka_mut().commit(
        Operation::Add(new_admin.clone()),
        ciphersuite,
        provider,
    )?;

    // The committer then generates a new tree
    let derived_tree = group_committer
        .tmka()
        .build_regeneration_tree(provider, ciphersuite);

    let encrypted_regeneration_tree = derived_tree.encrypt_hpke(provider, ciphersuite, new_admin.encryption_keypair()?.public_key());

    Ok((
        commit_broadcast_cgka,
        commit_unicast_cgka.unwrap(),
        encrypted_regeneration_tree,
    ))
}


pub fn add_admin_other_admins(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    commit_broadcast: CommitCGKABroadcast,
    username_committer: &String,
) -> Result<(), SumacError> {
    let binding = process_broadcast_cgka(
        all_admin_groups,
        username_committer,
        commit_broadcast,
        provider,
        ciphersuite,
    )?;
    Ok(binding)
}



pub fn add_admin_new_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    commit_unicast: CommitCGKAUnicast,
    encrypted_tree : EncryptedRegenerationTree,
    username_new_admin: &String
) -> Result<(), SumacError>{
    let new_admin = all_admins.get(username_new_admin).unwrap();
    let keypair_new_admin = new_admin.encryption_keypair()?;
    let private_key_new_admin = keypair_new_admin.private_key();

    let cgka = CGKAGroup::process_welcome(commit_unicast, provider, ciphersuite, new_admin)?;

    let regeneration_tree = RegenerationTree::decrypt_hpke(provider, ciphersuite, private_key_new_admin, encrypted_tree);

    let tree_tmka = TreeTMKA::from_ratchet_tree(regeneration_tree.tree);

    let tmka = TmkaAdminGroup{
        admin: new_admin.clone(),
        tree: tree_tmka,
        commit_secret: Secret::zero(ciphersuite),   // for now the commit secret is zero. It will get updated the next operation
    };

    let new_admin_group = SumacAdminGroup{
        identifier: username_new_admin.to_string(),
        cgka,
        tmka,
    };

    let res = all_admin_groups.insert(username_new_admin.to_string(), new_admin_group).is_none();
    assert!(res);

    Ok(())
}



pub fn add_admin_standard_users(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_users_group: &mut HashMap<String, SumacUserGroup>,
    username_new_admin: &String,
    username_committer : &String
) -> Result<(), SumacError> {
    for (_, user_group) in all_users_group.iter_mut() {
        let tree_committer = user_group
            .forest
            .get(username_committer)
            .unwrap();

        let own_leaf_node_index = tree_committer.own_leaf_index;
        let user = tree_committer.user.clone();
        let regeneration_set = tree_committer
            .build_regeneration_path(provider, ciphersuite, &own_leaf_node_index, true);



        //cerate a white tree and a new group, for now dumb
        let new_tree = tree_committer.generate_white_tree(ciphersuite);
        let mut new_group = TmkaSlaveGroup{
            tree: new_tree,
            own_leaf_index: own_leaf_node_index,
            user: user.clone(),
            commit_secret: Secret::zero(ciphersuite),
        };

        //replace the path by the content of the regeneration set
        let new_path = regeneration_set.secrets().into_iter().map(|(index, path_secret)| (*index, ParentNodeTMKA::new_from_path_secret(provider.crypto(), ciphersuite, path_secret.clone(), None).unwrap())).collect();
        new_group.replace_path(own_leaf_node_index, new_path)?;

        // also replace the leaf
        let new_leaf = LeafNodeTMKA::new(provider.crypto(), ciphersuite, user.credential_with_key().credential.clone(), Into::<MlsSecret>::into(regeneration_set.leaf_secret().unwrap().clone())).unwrap();
        new_group.replace_leaf(own_leaf_node_index, new_leaf);

        

        //insert the new tree in the forest
        let res = user_group.forest_mut().insert(username_new_admin.to_string(), new_group).is_none();
        assert!(res);
    }
    Ok(())
}





pub fn full_add_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    all_user_groups: &mut HashMap<String, SumacUserGroup>,
    username_new_admin: String,
    username_committer: String,
) -> Result<(), SumacError> {

    //////Committer's View/////////
    let (
        commit_broadcast_cgka,
        commit_unicast_cgka_admin,
        encrypted_regeneration_tree,
    ) = add_admin_committer(
        provider,
        ciphersuite,
        all_admins,
        all_admin_groups,
        &username_new_admin,
        &username_committer,
    )?;

    // //////////////////////////////////Other Admins' view////////////////////////////
    add_admin_other_admins(
        provider,
        ciphersuite,
        all_admin_groups,
        commit_broadcast_cgka,
        &username_committer,
    )?;


    // ////////////////////////////Standard Users' view////////////////////////////////


    add_admin_standard_users(
        provider,
        ciphersuite,
        all_user_groups,
        &username_new_admin,
        &username_committer
        )?;


    //////////////////////New admin's view//////////////////
    
    add_admin_new_admin(
        provider,
        ciphersuite,
        all_admins,
        all_admin_groups,
        commit_unicast_cgka_admin,
        encrypted_regeneration_tree,
        &username_new_admin
    )?;

    Ok(())
}




#[test]
fn test_add_admin(){
    let mut rng = rng();
    let provider  = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let  (mut all_admins, mut all_users, mut all_admins_groups, mut all_users_groups) = setup_sumac(&provider, ciphersuite, 10, 10).unwrap();

    assert_eq!(all_users_groups.len(), 1);


    for (username, _) in all_users.iter(){
        if username == "User_0"{
            continue;
        }
        full_add_user(&provider, ciphersuite, &mut all_admins, &all_users, &mut all_admins_groups, &mut all_users_groups, username.to_string(), "Admin_0".to_owned()).unwrap();

        check_sync_sumac(&all_admins_groups, &all_users_groups);
    }

    let mut committer_name = "Admin_0".to_string();

    for (admin_name, _) in all_admins.iter(){
        if admin_name == "Admin_0"{
            continue;
        }
        full_add_admin(&provider, ciphersuite, &all_admins, &mut all_admins_groups, &mut all_users_groups, admin_name.to_string(), committer_name).unwrap();

        check_sync_sumac(&all_admins_groups, &all_users_groups);
        committer_name = all_admins_groups.keys().choose(&mut rng).unwrap().to_string();
    }


    assert_eq!(all_admins_groups.len(), all_admins.len());
    assert_eq!(all_users_groups.len(), all_users.len());
}





/////////////////////:For benchmarks////////////////////

pub fn add_admin_only_one_other_admin(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    commit_broadcast: CommitCGKABroadcast,
    username_target_admin : &String
) -> Result<(), SumacError> {
    all_admin_groups.get_mut(username_target_admin).unwrap().cgka_mut().process(&commit_broadcast, provider, ciphersuite)?;
    Ok(())
}







pub fn add_admin_only_one_standard_user(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    user_group: &mut SumacUserGroup,
    username_committer : &String
) -> Result<(), SumacError> {

    let tree_committer = user_group
        .forest
        .get(username_committer)
        .unwrap();

    let own_leaf_node_index = tree_committer.own_leaf_index;
    let user = tree_committer.user.clone();
    let regeneration_set = tree_committer
        .build_regeneration_path(provider, ciphersuite, &own_leaf_node_index, true);



    //cerate a white tree and a new group, for now dumb
    let new_tree = tree_committer.generate_white_tree(ciphersuite);
    let mut new_group = TmkaSlaveGroup{
        tree: new_tree,
        own_leaf_index: own_leaf_node_index,
        user: user.clone(),
        commit_secret: Secret::zero(ciphersuite),
    };

    //replace the path by the content of the regeneration set
    let new_path = regeneration_set.secrets().into_iter().map(|(index, path_secret)| (*index, ParentNodeTMKA::new_from_path_secret(provider.crypto(), ciphersuite, path_secret.clone(), None).unwrap())).collect();
    new_group.replace_path(own_leaf_node_index, new_path)?;

    // also replace the leaf
    let new_leaf = LeafNodeTMKA::new(provider.crypto(), ciphersuite, user.credential_with_key().credential.clone(), Into::<MlsSecret>::into(regeneration_set.leaf_secret().unwrap().clone())).unwrap();
    new_group.replace_leaf(own_leaf_node_index, new_leaf);

    
    Ok(())
}
