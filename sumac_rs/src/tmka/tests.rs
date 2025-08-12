use std::collections::HashMap;

use openmls::prelude::Ciphersuite;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::{user::User, Operation};

use super::{user_group::TmkaSlaveGroup, CommitTMKABroadcast, TreeManager};




pub fn test_tmka(n_users: usize) {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
    let provider = OpenMlsRustCrypto::default();

    let master: TreeManager = User::initialize_user(String::from("master"), ciphersuite);

    let usernames: Vec<String> = (0..n_users).map(|i| format!("User_{}", i)).collect();



    let mut first_user = User::initialize_user(String::from("User_0"), ciphersuite);
    first_user.generate_key_package_bundle(ciphersuite, &provider);



    let mut all_users = HashMap::<&str, User>::new();
    let mut all_groups = HashMap::<&str, TmkaSlaveGroup>::new();

    let (mut master_group, mut slave_group) =
        master.create_tmka_group(&provider, ciphersuite, &first_user);
    all_users.insert("User_0", first_user.clone());

    all_groups.insert("User_0", slave_group);

    usernames.iter().skip(1).for_each(|username| {

        let mut new_user: User = User::initialize_user(String::from(username), ciphersuite);
        new_user.generate_key_package_bundle(ciphersuite, &provider);

        let (broadcast, welcome) =
            master_group.commit(Operation::Add(new_user.clone()), ciphersuite, &provider);

        // process the broadcast
        process_broadcast_tmka(&mut all_groups, broadcast, None, &provider, ciphersuite);

        // // process the welcome
        let new_group = TmkaSlaveGroup::process_welcome(
            welcome.expect("sHOULD BE A WELCOME"),
            &provider,
            ciphersuite,
            &new_user,
        );
        all_groups.insert(username, new_group);
        all_users.insert(username, new_user);
    });


    let (broadcast, _) = master_group.commit(
        Operation::Remove(all_users.get("User_1").unwrap().clone()),
        ciphersuite,
        &provider,
    );

    process_broadcast_tmka(
        &mut all_groups,
        broadcast,
        Some("User_1"),
        &provider,
        ciphersuite,
    );

    master_group.print_debug(&format!("Final state of the master group"));


    // print all the trees
    all_groups
        .iter()
        .filter(|(username, _)| **username != "User_1")
        .for_each(|(username, group)| {
            group.print_debug(&format!("View of User {}:", username));
        });
}







fn process_broadcast_tmka(
    all_groups: &mut HashMap<&str, TmkaSlaveGroup>,
    broadcast: CommitTMKABroadcast,
    target: Option<&str>,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) {
    // process the broadcast
    all_groups
        .iter_mut()
        .filter(|(username, _)| **username != target.unwrap_or("default"))
        .for_each(|(username, group)| {
            println!("{} is processing...", username);
            group.process(broadcast.clone(), provider, ciphersuite)
        });
}