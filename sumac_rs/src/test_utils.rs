use std::collections::HashMap;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};

use crate::{
    cgka::{CGKAGroup, CommitCGKABroadcast},
    errors::SumacError,
    sumac::SumacState,
    tmka::{
        admin_group::{TmkaAdminGroup},
        user_group::{TmkaSlaveGroup},
        CommitTMKABroadcast,
    },
    user::User,
};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

pub type UserPool = HashMap<String, User>;

pub fn setup_provider() -> OpenMlsRustCrypto {
    OpenMlsRustCrypto::default()
}

pub fn create_user(name: String, provider: &impl OpenMlsProvider) -> User {
    let mut user = User::initialize_user(name, CIPHERSUITE);
    user.generate_key_package_bundle(CIPHERSUITE, provider)
        .unwrap();
    user
}

pub fn create_pool_of_users(n: usize, provider: &impl OpenMlsProvider, prefix: String) -> UserPool {
    let mut pool = HashMap::with_capacity(n);
    for i in 0..n {
        let name = format!("{prefix}_{i}");
        let user = create_user(name.clone(), provider);
        pool.insert(name, user);
    }
    pool
}

pub fn check_sync_cgka(groups: &Vec<CGKAGroup>) {
    let first_commit_secret = &groups.get(0).unwrap().commit_secret;
    for group in groups.iter().skip(1) {
        assert_eq!(first_commit_secret, &group.commit_secret);
    }
}

pub fn check_sync_tmka(admin_group: &TmkaAdminGroup, user_groups: Vec<&TmkaSlaveGroup>) -> bool {
    let first_commit_secret = &admin_group.commit_secret;
    for group in user_groups.iter() {
        if first_commit_secret != &group.commit_secret {
            return false;
        };
    }
    true
}

pub fn check_sync_sumac(state: &SumacState) {
    // collect CGKAs without moving out of `state`
    let vec_cgka: Vec<_> = state
        .all_admin_groups
        .values()
        .map(|g| g.cgka().clone())
        .collect();

    check_sync_cgka(&vec_cgka);

    // iterate immutably over groups
    for (admin_name, admin_group) in state.all_admin_groups.iter() {
        let tmka_admin = admin_group.tmka().clone();

        // build users' TMKAs for this admin without moving from `state`
        let tmka_users: Vec<_> = state
            .all_user_groups
            .iter()
            .map(|(username, user_group)| {
                user_group
                    .forest()
                    .get(admin_name)
                    .unwrap_or_else(|| {
                        panic!(
                            "Tree of {} not in the forest of {}",
                            admin_name, username
                        )
                    })
                    
            })
            .collect();

        assert!(check_sync_tmka(&tmka_admin, tmka_users));
    }
}


// Util function for the test
pub fn process_broadcast_cgka(
    all_groups: &mut HashMap<String, CGKAGroup>,
    broadcast: CommitCGKABroadcast,
    committer: &str,
    target: Option<&str>,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<(), SumacError> {
    for (username, group) in all_groups.iter_mut() {
        if username != committer && username != target.unwrap_or("default") {
            // println!("-------processing {username}. Committer is {committer}-----");
            group.process(&broadcast, provider, ciphersuite)?;
        }
    }
    Ok(())
}

pub fn process_broadcast_tmka(
    all_groups: &mut HashMap<String, TmkaSlaveGroup>,
    broadcast: CommitTMKABroadcast,
    target: Option<&str>,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<(), SumacError> {
    for (username, group) in all_groups.iter_mut() {
        if username != target.unwrap_or("default") {
            group.process(&broadcast, provider, ciphersuite)?;
        }
    }
    Ok(())
}
