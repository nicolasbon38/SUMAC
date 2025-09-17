use std::collections::HashMap;

use openmls::{
    prelude::{Ciphersuite, LeafNodeIndex},
    tree_sumac::{
        nodes::{
            encryption_keys::SymmetricKey,
            traits::White,
        },
        LeafNodeTMKA,
    },
};
use openmls_traits::OpenMlsProvider;

use crate::{
    cgka::CGKAGroup,
    errors::SumacError,
    tmka::{
        admin_group::TmkaAdminGroup, generate_random_tmka,
        generate_random_tmka_memory_optimized_for_benchmarks, user_group::TmkaSlaveGroup,
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
    _identifier: String,
    cgka: CGKAGroup,
    tmka: TmkaAdminGroup,
    sumac_group_key: SymmetricKey,
}

#[derive(Clone)]
pub struct SumacUserGroup {
    forest: HashMap<String, TmkaSlaveGroup>,
    sumac_group_key: SymmetricKey,
}

impl SumacUserGroup {
    pub fn forest(&self) -> &HashMap<String, TmkaSlaveGroup> {
        &self.forest
    }

    pub fn forest_mut(&mut self) -> &mut HashMap<String, TmkaSlaveGroup> {
        &mut self.forest
    }

    pub fn update_group_key_from_tree(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        username_admin_tree: &String,
    ) -> Result<(), SumacError> {
        let secret = self
            .forest
            .get(username_admin_tree)
            .unwrap()
            .commit_secret
            .clone();
        let new_secret = secret.derive_secret(provider.crypto(), ciphersuite)?;
        self.sumac_group_key =
            SymmetricKey::derive_from_secret(provider.crypto(), ciphersuite, &new_secret.into())
                .map_err(|e| SumacError::MLSError(e))?;
        Ok(())
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

        let sumac_group_key = SymmetricKey::zero(ciphersuite);

        Ok((
            SumacAdminGroup {
                _identifier: self.identity(),
                cgka: self.create_group(provider, ciphersuite)?,
                tmka: tmka_admin_group,
                sumac_group_key: sumac_group_key.clone(),
            },
            SumacUserGroup {
                forest,
                sumac_group_key,
            },
        ))
    }
}

impl SumacAdminGroup {
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

    pub fn admin_key(&self) -> &SymmetricKey {
        &self.cgka().group_key
    }

    pub fn update_group_key_from_tree(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<SymmetricKey, SumacError> {
        let secret = self.tmka.commit_secret.clone();
        let new_secret = secret.derive_secret(provider.crypto(), ciphersuite)?;
        self.sumac_group_key =
            SymmetricKey::derive_from_secret(provider.crypto(), ciphersuite, &new_secret.into())
                .map_err(|e| SumacError::MLSError(e))?;
        Ok(self.sumac_group_key.clone())
    }

    pub fn update_group_key_from_cgka(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<SymmetricKey, SumacError> {
        let secret = self.cgka.commit_secret.clone();
        let new_secret = secret.derive_secret(provider.crypto(), ciphersuite)?;
        self.sumac_group_key =
            SymmetricKey::derive_from_secret(provider.crypto(), ciphersuite, &new_secret.into())
                .map_err(|e| SumacError::MLSError(e))?;
        Ok(self.sumac_group_key.clone())
    }
}

#[derive(Clone)]
pub struct SumacState {
    pub all_admins: HashMap<String, User>,
    pub all_users: HashMap<String, User>,
    pub all_admin_groups: HashMap<String, SumacAdminGroup>,
    pub all_user_groups: HashMap<String, SumacUserGroup>,
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


pub fn create_large_sumac_group(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: HashMap<String, User>,
    all_users: HashMap<String, User>,
) -> Result<SumacState, SumacError> {
    // create the admin cgkas
    let all_cgka_groups =
        CGKAGroup::generate_random_group(provider, ciphersuite, &all_admins, "Admin".to_string())?;

    // create all the tmkas
    let mut all_tmka_admin_groups = HashMap::new();
    let mut all_forests = HashMap::<String, HashMap<String, TmkaSlaveGroup>>::new();
    for username in all_users.keys() {
        all_forests.insert(username.clone(), HashMap::new());
    }

    for (admin_name, admin) in all_admins.iter() {
        let (admin_group, user_groups) =
            generate_random_tmka(provider, ciphersuite, &admin,& all_users)?;
        all_tmka_admin_groups.insert(admin_name.clone(), admin_group);
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
                _identifier: admin_name.clone(),
                cgka: all_cgka_groups.get(admin_name).unwrap().clone(),
                tmka: all_tmka_admin_groups.get(admin_name).unwrap().clone(),
                sumac_group_key: SymmetricKey::zero(ciphersuite),
            },
        );
    }

    for (user_name, _) in all_users.iter() {
        all_user_groups.insert(
            user_name.clone(),
            SumacUserGroup {
                forest: all_forests.get(user_name).unwrap().clone(),
                sumac_group_key: SymmetricKey::zero(ciphersuite),
            },
        );
    }

    Ok(SumacState {
        all_admins,
        all_users,
        all_admin_groups,
        all_user_groups,
    })
}


pub fn create_large_sumac_group_memory_optimized_for_benchmarks(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    all_admins: HashMap<String, User>,
    all_users: HashMap<String, User>,
    actual_admins_to_compute: &Vec<usize>,
    actual_users_to_compute: &Vec<usize>,
) -> Result<
    SumacState,
    SumacError,
> {
    // create the admin cgkas
    let all_cgka_groups = CGKAGroup::generate_random_group_memory_optimized_benchmark(
        provider,
        ciphersuite,
        &all_admins,
        "Admin".to_string(),
        actual_admins_to_compute,
    )?;

    // create all the tmkas

    let mut all_tmka_admin_groups = HashMap::new();
    let mut all_forests = HashMap::<String, HashMap<String, TmkaSlaveGroup>>::new();
    for index_user in actual_users_to_compute {
        let username = format!("User_{}", index_user);
        all_forests.insert(username.clone(), HashMap::new());
    }

    for (admin_name, admin) in all_admins.iter() {
        let (admin_group, user_groups) = generate_random_tmka_memory_optimized_for_benchmarks(
            provider,
            ciphersuite,
            &admin,
            &all_users,
            actual_users_to_compute,
        )?;
        all_tmka_admin_groups.insert(admin_name.clone(), admin_group);
        for (user, user_group) in user_groups {
            all_forests
                .get_mut(&user)
                .unwrap()
                .insert(admin_name.clone(), user_group.clone());
        }
    }

    let mut all_admin_groups = HashMap::new();
    let mut all_user_groups = HashMap::new();

    for index_admin in actual_admins_to_compute {
        let admin_name = format!("Admin_{}", index_admin);
        all_admin_groups.insert(
            admin_name.clone(),
            SumacAdminGroup {
                _identifier: admin_name.clone(),
                cgka: all_cgka_groups.get(&admin_name).unwrap().clone(),
                tmka: all_tmka_admin_groups.get(&admin_name).unwrap().clone(),
                sumac_group_key: SymmetricKey::zero(ciphersuite),
            },
        );
    }

    for index_user in actual_users_to_compute {
        let user_name = format!("User_{}", index_user);
        all_user_groups.insert(
            user_name.clone(),
            SumacUserGroup {
                forest: all_forests.get(&user_name).unwrap().clone(),
                sumac_group_key: SymmetricKey::zero(ciphersuite),
            },
        );
    }

    Ok(SumacState { all_admins, all_users, all_admin_groups, all_user_groups })
}
