
use std::collections::HashMap;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};

use crate::{cgka::{CGKAGroup, CommitCGKABroadcast}, errors::SumacError, sumac::{SumacAdminGroup, SumacUserGroup}, tmka::{admin_group::{self, TmkaAdminGroup}, user_group::{self, TmkaSlaveGroup}, CommitTMKABroadcast}, user::User};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

pub type UserPool = HashMap<String, User>;

pub fn setup_provider() -> OpenMlsRustCrypto{
    OpenMlsRustCrypto::default()
}


pub fn create_user(name: String, provider : &impl OpenMlsProvider) -> User{
    let mut user = User::initialize_user(name, CIPHERSUITE);
    user.generate_key_package_bundle(CIPHERSUITE, provider).unwrap();
    user
}


pub fn create_pool_of_users(
    n: usize,
    provider: &impl OpenMlsProvider,
    prefix : String
) -> UserPool {
    let mut pool = HashMap::with_capacity(n);
    for i in 0..n{
        let name = format!("{prefix}_{i}");
        let user = create_user(name.clone(), provider);
        pool.insert(name, user);
    }
    pool
}


pub fn check_sync_cgka(
    groups: &Vec<CGKAGroup>,
){
    let first_commit_secret = &groups.get(0).unwrap().commit_secret;
    for group in groups.iter().skip(1){
        assert_eq!(first_commit_secret, &group.commit_secret);
    }
}


pub fn check_sync_tmka(
    admin_group : &TmkaAdminGroup,
    user_groups: Vec<&TmkaSlaveGroup>,
) -> bool{
    let first_commit_secret = &admin_group.commit_secret;
    for group in user_groups.iter(){
        if first_commit_secret != &group.commit_secret{
            return false;
        };
    }
    true
}


pub fn check_sync_sumac(
    all_admins_groups : &HashMap<String, SumacAdminGroup>,
    all_users_groups : &HashMap<String, SumacUserGroup>
){
    let vec_cgka = all_admins_groups.into_iter().map(|sumac_admin_group| sumac_admin_group.1.cgka().clone()).collect();

    check_sync_cgka(&vec_cgka);



    for (admin_name, admin_group) in all_admins_groups{
        let tmka_admin = admin_group.tmka().clone();
        let mut tmka_users = vec![];
        for (username, user_group) in all_users_groups{
            let tmka_user = user_group.forest().get(admin_name).expect("Tree of {admin_name} not in the forest of {username}");
            tmka_users.push(tmka_user);
        }
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
            println!("-------processing {username}. Committer is {committer}-----");
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


