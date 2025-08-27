use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use openmls::{
    prelude::{Ciphersuite, Credential, HpkeCiphertext, LeafNodeIndex, ParentNodeIndex},
    tree_sumac::{OptionLeafNodeTMKA, OptionParentNodeTMKA, SumacTree},
};
use openmls_traits::OpenMlsProvider;
use rand::{rng, rngs::ThreadRng, seq::IteratorRandom, thread_rng, Rng};
use sumac_rs::{
    cgka::{CommitCGKABroadcast, CommitCGKAUnicast},
    crypto::types::AeadCiphertext,
    sumac::{
        create_large_sumac_group, create_large_sumac_group_memory_optimized_for_benchmarks,
        regeneration::{
            EncryptedCombinedPath, EncryptedRegenerationSet, EncryptedRegenerationSetHPKE,
            EncryptedRegenerationTree, RegenerationTree,
        },
        setup_sumac,
        sumac_operations::{
            add_admin::{
                add_admin_committer, add_admin_new_admin, add_admin_only_one_other_admin,
                add_admin_only_one_standard_user,
            },
            add_user::{
                add_user_committer, add_user_new_user, add_user_one_other_admin,
                add_user_one_standard_user, add_user_other_admins,
            },
            remove_admin::{
                remove_admin_committer, remove_admin_only_one_other_admin,
                remove_admin_only_one_standard_user,
            },
            remove_user::{
                remove_user_committer, remove_user_only_one_other_admin, remove_user_only_one_user,
            },
            update_user::{
                update_user_committer, update_user_only_one_other_admin,
                update_user_only_one_other_user, update_user_target_user,
            },
        },
        SumacAdminGroup, SumacUserGroup,
    },
    test_utils::{
        check_sync_sumac, create_pool_of_users, create_user, setup_provider, CIPHERSUITE,
    },
    tmka::{CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    user::User,
};

#[derive(Clone)]
struct SumacState {
    all_admins: HashMap<String, User>,
    all_users: HashMap<String, User>,
    all_admin_groups: HashMap<String, SumacAdminGroup>,
    all_user_groups: HashMap<String, SumacUserGroup>,
}

fn filling_sumac_group(n_admins: usize, n_users: usize) -> SumacState {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let mut all_admins = create_pool_of_users(n_admins, &provider, "Admin".to_owned());
    let mut all_users = create_pool_of_users(n_users, &provider, "User".to_owned());

    let (mut all_admin_groups, mut all_user_groups) =
        create_large_sumac_group(&provider, ciphersuite, &all_admins, &all_users).unwrap();

    check_sync_sumac(&all_admin_groups, &all_user_groups);

    SumacState {
        all_admins,
        all_users,
        all_admin_groups,
        all_user_groups,
    }
}

fn filling_sumac_group_memory_optimized(n_admins: usize, n_users: usize) -> SumacState {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let mut all_admins = create_pool_of_users(n_admins, &provider, "Admin".to_owned());
    let mut all_users = create_pool_of_users(n_users, &provider, "User".to_owned());

    // Sample three random admins
    let mut rng = thread_rng();
    let index_admin_1 = rng.gen_range(0..n_admins);
    let mut index_admin_2 = rng.gen_range(0..n_admins);
    while index_admin_1 == index_admin_2 {
        index_admin_2 = rng.gen_range(0..n_admins);
    }
    let mut index_admin_3 = rng.gen_range(0..n_admins);
    while (index_admin_1 == index_admin_3) || (index_admin_2 == index_admin_3) {
        index_admin_3 = rng.gen_range(0..n_admins);
    }

    // Sample three random users
    let index_user_1 = rng.gen_range(0..n_users);
    let mut index_user_2 = rng.gen_range(0..n_users);
    while index_user_1 == index_user_2 {
        index_user_2 = rng.gen_range(0..n_users);
    }
    let mut index_user_3 = rng.gen_range(0..n_users);
    while (index_user_1 == index_user_3) || (index_user_2 == index_user_3) {
        index_user_3 = rng.gen_range(0..n_users);
    }

    let (mut all_admin_groups, mut all_user_groups) =
        create_large_sumac_group_memory_optimized_for_benchmarks(
            &provider,
            ciphersuite,
            &all_admins,
            &all_users,
            &vec![index_admin_1, index_admin_2, index_admin_3],
            &vec![index_user_1, index_user_2, index_user_3],
        )
        .unwrap();

    check_sync_sumac(&all_admin_groups, &all_user_groups);

    SumacState {
        all_admins,
        all_users,
        all_admin_groups,
        all_user_groups,
    }
}

fn add_user_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_users: usize,
    username_committer: &String,
) -> (
    CommitTMKABroadcast,
    CommitTMKAUnicast,
    HashMap<String, EncryptedRegenerationSetHPKE>,
    LeafNodeIndex,
    AeadCiphertext,
) {
    add_user_committer(
        provider,
        ciphersuite,
        &mut state.all_users,
        &state.all_admins,
        &mut state.all_admin_groups,
        &format!("User_{}", n_users),
        &username_committer,
    )
    .unwrap()
}

fn add_user_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_users: usize,
    encrypted_regeneration_set: &EncryptedRegenerationSetHPKE,
    username_committer: &String,
    target_admin_name: &String,
) {
    assert_ne!(username_committer, target_admin_name);
    let username_new_user = format!("User_{}", n_users);
    let new_user = state.all_users.get(&username_new_user).unwrap();
    let committer = state.all_admins.get(username_committer).unwrap();
    let target_admin_group = state.all_admin_groups.get_mut(target_admin_name).unwrap();

    add_user_one_other_admin(
        provider,
        ciphersuite,
        &state.all_admins,
        &state.all_users,
        target_admin_group,
        target_admin_name,
        &username_new_user,
        encrypted_regeneration_set,
    )
    .unwrap()
}

fn add_user_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_new_user: &LeafNodeIndex,
    username_committer: &String,
    username_target_user: &String,
) {
    let mut user_group = state.all_user_groups.get_mut(username_target_user).unwrap();

    add_user_one_standard_user(
        provider,
        ciphersuite,
        &mut user_group,
        username_committer.to_string(),
        commit_broadcast_tmka,
        leaf_index_new_user,
    )
    .unwrap()
}

fn add_user_sumac_new_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_new_user: String,
    username_committer: String,
    commit_unicast_tmka_admin: CommitTMKAUnicast,
    welcome_new_user: HashMap<String, (TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>,
    leaf_index_new_user: &LeafNodeIndex,
) {
    add_user_new_user(
        provider,
        ciphersuite,
        &state.all_users,
        username_new_user,
        username_committer,
        commit_unicast_tmka_admin,
        welcome_new_user,
        leaf_index_new_user,
    )
    .unwrap();
}

fn benchmark_add_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("add-user_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for (n_admins, n_users) in vec![256, 16, 4]
        .into_iter()
        .zip(vec![1 << 16, 256, 16].into_iter())
    {
        let mut state: SumacState = filling_sumac_group_memory_optimized(n_admins, n_users);
        let new_user_name = format!("User_{}", n_users);
        let new_user = create_user(new_user_name.clone(), &provider);
        state.all_users.insert(new_user_name.clone(), new_user);

        // -------- Committer --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(add_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_users,
                            &username_committer,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other Admin --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_, _, encrypted_regeneration_sets, _, encrypted_group_key) =
                            add_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_users,
                                &username_committer,
                            );

                        let target_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let encrypted_regeneration_set =
                            encrypted_regeneration_sets.get(&target_admin).unwrap();

                        let t0 = Instant::now();
                        let _ = black_box(add_user_sumac_one_other_admin(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_users,
                            &encrypted_regeneration_set,
                            &username_committer,
                            &target_admin,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Standard Users --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Standard Users:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (
                            commit_broadcast,
                            _,
                            encrypted_regeneration_sets,
                            leaf_index_new_user,
                            encrypted_group_key,
                        ) = add_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_users,
                            &username_committer,
                        );

                        let target_user: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(add_user_sumac_one_standard_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            commit_broadcast,
                            &leaf_index_new_user,
                            &username_committer,
                            &target_user,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- New User --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("New User:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (
                            commit_broadcast,
                            commit_unicast,
                            encrypted_regeneration_sets,
                            leaf_index_new_user,
                            encrypted_group_key,
                        ) = add_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_users,
                            &username_committer,
                        );

                        let welcome_new_user = add_user_other_admins(
                            &provider,
                            ciphersuite,
                            &state.all_admins,
                            &state.all_users,
                            &mut local_state.all_admin_groups,
                            &new_user_name,
                            &username_committer,
                            &encrypted_group_key,
                            &encrypted_regeneration_sets,
                        )
                        .unwrap();

                        let t0 = Instant::now();
                        let _ = black_box(add_user_sumac_new_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            new_user_name.clone(),
                            username_committer.to_string(),
                            commit_unicast,
                            welcome_new_user,
                            &leaf_index_new_user,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );
    }

    group.finish();
}

fn add_admin_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_admins: usize,
    username_committer: &String,
) -> (
    CommitCGKABroadcast,
    CommitCGKAUnicast,
    EncryptedRegenerationTree,
    AeadCiphertext,
) {
    add_admin_committer(
        provider,
        ciphersuite,
        &mut state.all_admins,
        &mut state.all_admin_groups,
        &format!("Admin_{}", n_admins),
        &username_committer,
    )
    .unwrap()
}

fn add_admin_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast: CommitCGKABroadcast,
    username_target_admin: &String,
) {
    add_admin_only_one_other_admin(
        provider,
        ciphersuite,
        &mut state.all_admin_groups,
        commit_broadcast,
        username_target_admin,
    )
    .unwrap()
}

fn add_admin_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    encrypted_group_key: AeadCiphertext,
    username_new_admin: &String,
) {
    let user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    add_admin_only_one_standard_user(
        provider,
        ciphersuite,
        user_group,
        encrypted_group_key,
        username_committer,
        username_new_admin,
    )
    .unwrap()
}

fn add_admin_sumac_new_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_unicast: CommitCGKAUnicast,
    encrypted_tree: EncryptedRegenerationTree,
    username_new_admin: &String,
) {
    add_admin_new_admin(
        provider,
        ciphersuite,
        &state.all_admins,
        &mut state.all_admin_groups,
        commit_unicast,
        encrypted_tree,
        username_new_admin,
    )
    .unwrap()
}

fn benchmark_add_admin(c: &mut Criterion) {
    let mut group = c.benchmark_group("add-admin_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for (n_admins, n_users) in vec![256, 16, 4]
        .into_iter()
        .zip(vec![1 << 16, 256, 16].into_iter())
    {
        let mut state: SumacState = filling_sumac_group_memory_optimized(n_admins, n_users);
        let new_admin_name = format!("Admin_{}", n_admins);
        let new_admin = create_user(new_admin_name.clone(), &provider);
        state.all_admins.insert(new_admin_name.clone(), new_admin);

        // -------- Committer --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(add_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other Admin --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _, _, _) = add_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                        );

                        let target_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(add_admin_sumac_one_other_admin(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            commit_broadcast,
                            &target_admin,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Standard User --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_, _, _, encrypted_group_key) = add_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                        );

                        let target_user: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(add_admin_sumac_one_standard_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &target_user,
                            encrypted_group_key,
                            &format!("Admin_{n_admins}").to_string(),
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- New Admin --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("New Admin:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_, commit_unicast, encrypted_tree, _) = add_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                        );

                        let t0 = Instant::now();
                        let _ = black_box(add_admin_sumac_new_admin(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            commit_unicast,
                            encrypted_tree,
                            &new_admin_name,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );
    }
}

fn update_user_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_updated_user: &String,
) -> (
    CommitTMKABroadcast,
    CommitTMKAUnicast,
    HashMap<String, EncryptedCombinedPath>,
    LeafNodeIndex,
    AeadCiphertext,
) {
    update_user_committer(
        provider,
        ciphersuite,
        &mut state.all_users,
        &state.all_admins,
        &mut state.all_admin_groups,
        username_updated_user,
        &username_committer,
    )
    .unwrap()
}

fn update_user_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_to_update: &String,
    username_committer: &String,
    username_target_admin: &String,
    encrypted_group_key: AeadCiphertext,
    encrypted_regeneration_set: &EncryptedRegenerationSetHPKE,
) {
    let mut admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();
    update_user_only_one_other_admin(
        provider,
        ciphersuite,
        &state.all_admins,
        &state.all_users,
        &mut admin_group,
        username_target_admin,
        username_to_update,
        &encrypted_group_key,
        encrypted_regeneration_set,
    )
    .unwrap()
}

fn update_user_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    commit_broadcast_tmka: &CommitTMKABroadcast,
    leaf_index_updated_user: &LeafNodeIndex,
) {
    let mut user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    update_user_only_one_other_user(
        provider,
        ciphersuite,
        &mut user_group,
        username_committer,
        commit_broadcast_tmka,
        leaf_index_updated_user,
    )
    .unwrap()
}

fn update_user_sumac_updated_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_unicast: CommitTMKAUnicast,
    username_committer: &String,
    username_updated_user: &String,
    leaf_index_updated_user: &LeafNodeIndex,
) {
    update_user_target_user(
        provider,
        ciphersuite,
        &mut state.all_user_groups,
        username_committer,
        commit_unicast,
        leaf_index_updated_user,
        username_updated_user,
    )
    .unwrap()
}
fn benchmark_update_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("update-user_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for (n_admins, n_users) in vec![256, 16, 4]
        .into_iter()
        .zip(vec![1 << 16, 256, 16].into_iter())
    {
        let state: SumacState = filling_sumac_group_memory_optimized(n_admins, n_users);

        // -------- Committer --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_updated_user: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(update_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_updated_user,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other Admin --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_update: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (
                            commit_broadcast,
                            _,
                            encrypted_regeneration_sets,
                            _,
                            encrypted_group_key,
                        ) = update_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_to_update,
                        );

                        let username_target_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let encrypted_regeneration_set = encrypted_regeneration_sets
                            .get(&username_target_admin)
                            .unwrap();

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(update_user_sumac_one_other_admin(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_to_update,
                            &username_committer,
                            &username_target_admin,
                            encrypted_group_key,
                            &encrypted_regeneration_set,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Standard User --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_update: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_target_user: String = local_state
                            .all_user_groups
                            .keys()
                            .filter(|u| **u != username_to_update)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _, _, leaf_index, _) = update_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_to_update,
                        );

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(update_user_sumac_one_standard_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_target_user,
                            &commit_broadcast,
                            &leaf_index,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Target User --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Target User:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_update: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_cb, commit_unicast, _ers, leaf_index, _) =
                            update_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_to_update,
                            );

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(update_user_sumac_updated_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            commit_unicast,
                            &username_committer,
                            &username_to_update,
                            &leaf_index,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );
    }
}

fn remove_user_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_removed_user: &String,
) -> (
    CommitTMKABroadcast,
    HashMap<String, EncryptedRegenerationSetHPKE>,
    LeafNodeIndex,
    AeadCiphertext,
) {
    remove_user_committer(
        provider,
        ciphersuite,
        &mut state.all_users,
        &state.all_admins,
        &mut state.all_admin_groups,
        username_removed_user,
        &username_committer,
    )
    .unwrap()
}

fn remove_user_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_admin: &String,
    encrypted_group_key: AeadCiphertext,
    encrypted_regeneration_sets: &HashMap<String, EncryptedRegenerationSetHPKE>,
    leaf_index_to_remove: &LeafNodeIndex,
) {
    let mut admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();
    remove_user_only_one_other_admin(
        provider,
        ciphersuite,
        &state.all_admins,
        &mut admin_group,
        username_committer,
        username_target_admin,
        encrypted_regeneration_sets,
        &encrypted_group_key,
        leaf_index_to_remove,
    )
    .unwrap()
}

fn remove_user_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    commit_broadcast_tmka: &CommitTMKABroadcast,
    leaf_index_removed_user: &LeafNodeIndex,
) {
    remove_user_only_one_user(
        provider,
        ciphersuite,
        &mut state.all_user_groups,
        username_committer,
        &commit_broadcast_tmka,
        leaf_index_removed_user,
        username_target_user,
    )
    .unwrap()
}

fn benchmark_remove_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove-user_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for (n_admins, n_users) in vec![256, 16, 4]
        .into_iter()
        .zip(vec![1 << 16, 256, 16].into_iter())
    {
        let state: SumacState = filling_sumac_group_memory_optimized(n_admins, n_users);

        // -------- Committer --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_removed_user: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(remove_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_removed_user,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other Admin --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_remove: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_cb, encrypted_regeneration_sets, leaf_index, encrypted_group_key) =
                            remove_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_to_remove,
                            );

                        let username_target_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(remove_user_sumac_one_other_admin(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_target_admin,
                            encrypted_group_key,
                            &encrypted_regeneration_sets,
                            &leaf_index,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Standard User --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // setup (NOT TIMED)
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_remove: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_target_user: String = local_state
                            .all_user_groups
                            .keys()
                            .filter(|u| **u != username_to_remove)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _ers, leaf_index, _) = remove_user_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_to_remove,
                        );

                        // timed
                        let t0 = Instant::now();
                        let _ = black_box(remove_user_sumac_one_standard_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_target_user,
                            &commit_broadcast,
                            &leaf_index,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );
    }
}

fn remove_admin_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_admins: usize,
    username_committer: &String,
    username_removed_admin: &String,
) -> (CommitCGKABroadcast, AeadCiphertext) {
    remove_admin_committer(
        provider,
        ciphersuite,
        &mut state.all_admins,
        &mut state.all_admin_groups,
        username_removed_admin,
        &username_committer,
    )
    .unwrap()
}

fn remove_admin_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast: CommitCGKABroadcast,
    username_target_admin: &String,
) {
    remove_admin_only_one_other_admin(
        provider,
        ciphersuite,
        &mut state.all_admin_groups,
        commit_broadcast,
        username_target_admin,
    )
    .unwrap()
}

fn remove_admin_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    username_removed_admin: &String,
    encrypted_group_key: AeadCiphertext,
) {
    let user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    remove_admin_only_one_standard_user(
        provider,
        ciphersuite,
        user_group,
        encrypted_group_key,
        username_committer,
        username_removed_admin,
    )
    .unwrap()
}

fn benchmark_remove_admin(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove-admin_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for (n_admins, n_users) in vec![256, 16, 4]
        .into_iter()
        .zip(vec![1 << 16, 256, 16].into_iter())
    {
        let mut state: SumacState = filling_sumac_group_memory_optimized(n_admins, n_users);

        // -------- Committer --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let username_removed_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|key| **key != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(remove_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                            &username_removed_admin,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other Admin --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let username_removed_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|key| **key != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _) = remove_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                            &username_removed_admin,
                        );

                        let target_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|candidate| {
                                (**candidate != username_committer)
                                    && (**candidate != username_removed_admin)
                            })
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(remove_admin_sumac_one_other_admin(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            commit_broadcast,
                            &target_admin,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Standard User --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_admin_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let username_removed_admin: String = local_state
                            .all_admin_groups
                            .keys()
                            .filter(|key| **key != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_, encypted_group_key) = remove_admin_sumac_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            n_admins,
                            &username_committer,
                            &username_removed_admin,
                        );

                        let target_user: String = local_state
                            .all_user_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let t0 = Instant::now();
                        let _ = black_box(remove_admin_sumac_one_standard_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &target_user,
                            &username_removed_admin,
                            encypted_group_key,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );
    }
}

criterion_group!(
    bench_sumac,
    benchmark_remove_admin,
    benchmark_add_admin,
    benchmark_add_user,
    benchmark_update_user,
    benchmark_remove_user,
);
criterion_main!(bench_sumac);
