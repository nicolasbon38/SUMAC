use std::{collections::HashMap, fmt::format};

use openmls::{
    prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex, ParentNodeIndex},
    tree_sumac::{
        nodes::{encryption_keys::KeyPairRef, traits::White},
        LeafNodeTMKA,
    },
};
use openmls_traits::OpenMlsProvider;

use crate::{
    cgka::{CGKAGroup, CommitCGKABroadcast},
    crypto::{hpke::hpke_encrypt_secret, secret::Secret},
    errors::SumacError,
    sumac::{
        regeneration::{EncryptedCombinedPath, RegenerationSet},
        sumac_operations::{add_admin::full_add_admin, add_user::full_add_user},
    },
    test_utils::{
        check_sync_sumac, create_pool_of_users, create_user, setup_provider, CIPHERSUITE,
    },
    tmka::{
        admin_group::TmkaAdminGroup, generate_random_tmka, user_group::TmkaSlaveGroup,
        CommitTMKABroadcast, TreeManager, TreeTMKA,
    },
    user::User,
};

pub mod regeneration;
pub mod sumac_operations;

pub enum OperationSUMAC {
    AddUser(User),
}

#[derive(Clone)]
pub struct SumacAdminGroup {
    identifier: String,
    cgka: CGKAGroup,
    tmka: TmkaAdminGroup,
}

#[derive(Clone)]
pub struct SumacUserGroup {
    forest: HashMap<String, TmkaSlaveGroup>,
}

impl SumacUserGroup {
    pub fn forest(&self) -> &HashMap<String, TmkaSlaveGroup> {
        &self.forest
    }

    pub fn forest_mut(&mut self) -> &mut HashMap<String, TmkaSlaveGroup> {
        &mut self.forest
    }
}

impl User {
    pub fn create_sumac_group(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        first_user: &User,
    ) -> Result<(SumacAdminGroup, SumacUserGroup), SumacError> {
        let (tmka_admin_group, tmka_user_group) =
            self.create_tmka_group(provider, ciphersuite, &first_user)?;

        let mut forest = HashMap::new();
        forest.insert(self.identity(), tmka_user_group);

        Ok((
            SumacAdminGroup {
                identifier: self.identity(),
                cgka: self.create_group(provider, ciphersuite)?,
                tmka: tmka_admin_group,
            },
            SumacUserGroup { forest },
        ))
    }
}

impl SumacAdminGroup {
    pub fn commit(
        &mut self,
        op: OperationSUMAC,
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
    ) {
        todo!(); // Eventually we will factorize every operation in this methode
    }

    pub fn cgka(&self) -> &CGKAGroup {
        &self.cgka
    }

    pub fn cgka_mut(&mut self) -> &mut CGKAGroup {
        &mut self.cgka
    }

    pub fn tmka(&self) -> &TmkaAdminGroup {
        &self.tmka
    }

    pub fn tmka_mut(&mut self) -> &mut TmkaAdminGroup {
        &mut self.tmka
    }
}

fn process_broadcast_cgka(
    all_admin_groups: &mut HashMap<String, SumacAdminGroup>,
    identifier_admin_committer: &String,
    broadcast: CommitCGKABroadcast,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<(), SumacError> {
    // process the broadcast
    for (name, group) in all_admin_groups.iter_mut() {
        if name != identifier_admin_committer {
            group
                .cgka_mut()
                .process(&broadcast, provider, ciphersuite)?;
        }
    }
    Ok(())
}

fn process_broadcast_tmka(
    all_users_groups: &mut HashMap<String, SumacUserGroup>,
    identifier_admin_committer: &String,
    broadcast: CommitTMKABroadcast,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<(), SumacError> {
    // process the broadcast
    all_users_groups.iter_mut().for_each(|(_, group)| {
        group
            .forest_mut()
            .get_mut(identifier_admin_committer)
            .unwrap()
            .process(&broadcast, provider, ciphersuite)
            .unwrap()
    });
    Ok(())
}

fn process_regeneration_procedure_admin(
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

impl TmkaAdminGroup {
    pub fn add_placeholder_leaf(&mut self, ciphersuite: Ciphersuite) -> LeafNodeIndex {
        let mut diff = self.tree.empty_diff();
        let leaf_index = diff
            .add_leaf(LeafNodeTMKA::white(ciphersuite).into())
            .unwrap();
        self.tree.merge_diff(diff.into_staged_diff().unwrap());
        leaf_index
    }
}

pub fn setup_sumac(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_admins: usize,
    n_users: usize,
) -> Result<
    (
        HashMap<String, User>,
        HashMap<String, User>,
        HashMap<String, SumacAdminGroup>,
        HashMap<String, SumacUserGroup>,
    ),
    SumacError,
> {
    // Generate a bunch of admins and users, with their personal keys
    let all_admins = create_pool_of_users(n_admins, provider, "Admin".to_owned());
    let all_users = create_pool_of_users(n_users, provider, "User".to_owned());

    let mut all_admin_groups = HashMap::<String, SumacAdminGroup>::new();
    let mut all_user_groups = HashMap::<String, SumacUserGroup>::new();

    // Create a Sumac Group, with one admin and one standard user.
    let first_admin = all_admins.get("Admin_0").unwrap();
    let first_user = all_users.get("User_0").unwrap();

    let (admin_group_0, user_group_0) =
        first_admin.create_sumac_group(provider, ciphersuite, first_user)?;

    //Put the group views in the container
    all_user_groups.insert("User_0".to_owned(), user_group_0);
    all_admin_groups.insert("Admin_0".to_owned(), admin_group_0);

    Ok((all_admins, all_users, all_admin_groups, all_user_groups))
}

pub fn create_large_sumac_group(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: &HashMap<String, User>,
    all_users: &HashMap<String, User>,
) -> Result<
    (
        HashMap<String, SumacAdminGroup>,
        HashMap<String, SumacUserGroup>,
    ),
    SumacError,
> {
    // create the admin cgkas
    let all_cgka_groups =
        CGKAGroup::generate_random_group(provider, ciphersuite, all_admins, "Admin".to_string())?;

    // create all the tmkas
    let mut all_tmka_admin_groups = HashMap::new();
    let mut all_forests = HashMap::<String, HashMap<String, TmkaSlaveGroup>>::new();
    for username in all_users.keys() {
        all_forests.insert(username.clone(), HashMap::new());
    }

    for (admin_name, admin) in all_admins {
        let (admin_group, user_groups) =
            generate_random_tmka(provider, ciphersuite, admin, all_users)?;
        all_tmka_admin_groups.insert(admin_name, admin_group);
        for (user, user_group) in user_groups {
            all_forests
                .get_mut(&user)
                .unwrap()
                .insert(admin_name.clone(), user_group.clone());
        }
    }

    let mut all_admin_groups = HashMap::new();
    let mut all_user_groups = HashMap::new();

    for (admin_name, _) in all_admins.iter() {
        all_admin_groups.insert(
            admin_name.clone(),
            SumacAdminGroup {
                identifier: admin_name.clone(),
                cgka: all_cgka_groups.get(admin_name).unwrap().clone(),
                tmka: all_tmka_admin_groups.get(admin_name).unwrap().clone(),
            },
        );
    }

    for (user_name, _) in all_users.iter() {
        all_user_groups.insert(
            user_name.clone(),
            SumacUserGroup {
                forest: all_forests.get(user_name).unwrap().clone(),
            },
        );
    }

    Ok((all_admin_groups, all_user_groups))
}

#[test]
fn test_large_sumac_group() {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let mut all_admins = create_pool_of_users(10, &provider, "Admin".to_owned());
    let mut all_users = create_pool_of_users(10, &provider, "User".to_owned());

    let (mut all_admin_groups, mut all_user_groups) =
        create_large_sumac_group(&provider, ciphersuite, &all_admins, &all_users).unwrap();

    check_sync_sumac(&all_admin_groups, &all_user_groups);

    let new_admin_name = format!("Admin_{}", 10);
    let new_admin = create_user(new_admin_name.clone(), &provider);
    all_admins.insert(new_admin_name.clone(), new_admin);

    full_add_admin(
        &provider,
        ciphersuite,
        &all_admins,
        &mut all_admin_groups,
        &mut all_user_groups,
        new_admin_name,
        "Admin_5".to_owned(),
    )
    .unwrap();

    check_sync_sumac(&all_admin_groups, &all_user_groups);

    println!("Add-Admin ok !");
    let new_user_name = format!("User_{}", 10);
    let new_user = create_user(new_user_name.clone(), &provider);
    all_users.insert(new_user_name.clone(), new_user);
    full_add_user(
        &provider,
        ciphersuite,
        &all_admins,
        &all_users,
        &mut all_admin_groups,
        &mut all_user_groups,
        new_user_name,
        "Admin_4".to_owned(),
    )
    .unwrap();
}
