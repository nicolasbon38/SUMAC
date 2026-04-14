use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use openmls::prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex};
use openmls_traits::OpenMlsProvider;
use rand::{rng, rngs::ThreadRng, seq::IteratorRandom, Rng};
use sumac_rs::{
    cgka::{CommitCGKABroadcast, CommitCGKAUnicast},
    crypto::types::AeadCiphertext,
    sumac::{
        create_large_sumac_group, create_large_sumac_group_memory_optimized_for_benchmarks,
        regeneration::{
            EncryptedCombinedPath, EncryptedRegenerationSetHPKE, EncryptedRegenerationTree,
        },
        sumac_operations::{
            op_admin::{
                op_admin_committer, op_admin_one_other_admin, op_admin_one_standard_user,
                op_admin_target_admin,
            },
            op_user::{
                op_user_committer, op_user_one_other_admin, op_user_one_standard_user,
                op_user_other_admins, op_user_target_user, WelcomeNewUser,
            },
        },
        SumacState,
    },
    test_utils::{
        check_sync_sumac, create_pool_of_users, create_user, setup_provider, CIPHERSUITE,
    },
    tmka::{CommitTMKABroadcast, CommitTMKAUnicast, TreeTMKA},
    Operation,
};

fn filling_sumac_group(n_admins: usize, n_users: usize) -> SumacState {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let all_admins = create_pool_of_users(n_admins, &provider, "Admin".to_owned());
    let all_users = create_pool_of_users(n_users, &provider, "User".to_owned());

    let state = create_large_sumac_group(&provider, ciphersuite, all_admins, all_users).unwrap();

    check_sync_sumac(&state);

    state
}

fn _filling_sumac_group_memory_optimized(n_admins: usize, n_users: usize) -> SumacState {
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    let all_admins = create_pool_of_users(n_admins, &provider, "Admin".to_owned());
    let all_users = create_pool_of_users(n_users, &provider, "User".to_owned());

    // Sample three random admins
    let mut rng = rng();
    let index_admin_1 = rng.random_range(0..n_admins);
    let mut index_admin_2 = rng.random_range(0..n_admins);
    while index_admin_1 == index_admin_2 {
        index_admin_2 = rng.random_range(0..n_admins);
    }
    let mut index_admin_3 = rng.random_range(0..n_admins);
    while (index_admin_1 == index_admin_3) || (index_admin_2 == index_admin_3) {
        index_admin_3 = rng.random_range(0..n_admins);
    }

    // Sample three random users
    let index_user_1 = rng.random_range(0..n_users);
    let mut index_user_2 = rng.random_range(0..n_users);
    while index_user_1 == index_user_2 {
        index_user_2 = rng.random_range(0..n_users);
    }
    let mut index_user_3 = rng.random_range(0..n_users);
    while (index_user_1 == index_user_3) || (index_user_2 == index_user_3) {
        index_user_3 = rng.random_range(0..n_users);
    }

    let state = create_large_sumac_group_memory_optimized_for_benchmarks(
        &provider,
        ciphersuite,
        all_admins,
        all_users,
        &vec![index_admin_1, index_admin_2, index_admin_3],
        &vec![index_user_1, index_user_2, index_user_3],
    )
    .unwrap();

    check_sync_sumac(&state);

    state
}

fn add_user_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_users: usize,
    username_committer: &String,
) -> (
    CommitTMKABroadcast,
    Option<CommitTMKAUnicast>,
    HashMap<String, EncryptedRegenerationSetHPKE>,
    LeafNodeIndex,
    AeadCiphertext,
) {
    let username_to_add = format!("User_{}", n_users);
    let user_to_add = state.all_users.get(&username_to_add).unwrap();
    op_user_committer(
        &Operation::Add(user_to_add.clone()),
        provider,
        ciphersuite,
        state,
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
    encrypted_group_key: AeadCiphertext,
    username_committer: &String,
    target_admin_name: &String,
) {
    assert_ne!(username_committer, target_admin_name);
    let username_new_user = format!("User_{}", n_users);
    let new_user = state.all_users.get(&username_new_user).unwrap();
    let current_admin_group = state.all_admin_groups.get_mut(target_admin_name).unwrap();
    let current_admin = state.all_admins.get(target_admin_name).unwrap();

    op_user_one_other_admin(
        &Operation::Add(new_user.clone()),
        provider,
        ciphersuite,
        current_admin,
        current_admin_group,
        encrypted_group_key,
        encrypted_regeneration_set,
    )
    .unwrap();
}

fn add_user_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_new_user: &LeafNodeIndex,
    username_committer: &String,
    username_new_user: &String,
) {
    let user_group = state.all_user_groups.get_mut(username_new_user).unwrap();
    let new_user = state.all_users.get_mut(username_new_user).unwrap();

    op_user_one_standard_user(
        &Operation::Add(new_user.clone()),
        provider,
        ciphersuite,
        user_group,
        username_committer,
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
    commit_unicast_tmka_admin: Option<CommitTMKAUnicast>,
    welcome_new_user: Option<HashMap<String, (TreeTMKA, HpkeCiphertext, EncryptedCombinedPath)>>,
    leaf_index_new_user: &LeafNodeIndex,
) {
    let new_user = state.all_users.get_mut(&username_new_user).unwrap();

    op_user_target_user(
        &Operation::Add(new_user.clone()),
        provider,
        ciphersuite,
        state,
        &username_committer,
        &username_new_user,
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


    let mut rng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for n_admins in vec![10, 50, 100, 150, 200] {
        for n_users in vec![100, 400, 700, 1000] {
            let mut state: SumacState = filling_sumac_group(n_admins, n_users);
            let new_user_name = format!("User_{}", n_users);
            let new_user = create_user(new_user_name.clone(), &provider);
            state
                .all_users
                .insert(new_user_name.clone(), new_user.clone());

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

                            let (commit_broadcast, _, _, leaf_index_new_user, _) =
                                add_user_sumac_committer(
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
                                encrypted_group_key,
                                &username_committer,
                                &target_admin,
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
                                _,
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

                            let welcome_new_user = op_user_other_admins(
                                &Operation::Add(new_user.clone()),
                                &provider,
                                ciphersuite,
                                &mut local_state,
                                &username_committer,
                                encrypted_group_key,
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
    }

    group.finish();
}

fn add_admin_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_new_admin: &String,
) -> (
    CommitCGKABroadcast,
    Option<CommitCGKAUnicast>,
    Option<EncryptedRegenerationTree>,
    AeadCiphertext,
) {
    let new_admin = state.all_admins.get(username_new_admin).unwrap();
    op_admin_committer(
        &Operation::Add(new_admin.clone()),
        provider,
        ciphersuite,
        state,
        username_committer,
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
    let admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();

    op_admin_one_other_admin(provider, ciphersuite, admin_group, &commit_broadcast).unwrap()
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
    let new_admin = state.all_admins.get(username_new_admin).unwrap();
    op_admin_one_standard_user(
        &Operation::Add(new_admin.clone()),
        provider,
        ciphersuite,
        user_group,
        &encrypted_group_key,
        username_committer,
    )
    .unwrap()
}

fn add_admin_sumac_new_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast: CommitCGKABroadcast,
    commit_unicast: Option<CommitCGKAUnicast>,
    encrypted_tree: Option<EncryptedRegenerationTree>,
    username_new_admin: &String,
) {
    let new_admin = state.all_admins.get(username_new_admin).unwrap();

    op_admin_target_admin(
        &Operation::Add(new_admin.clone()),
        provider,
        ciphersuite,
        state,
        commit_broadcast,
        commit_unicast,
        encrypted_tree,
    )
    .unwrap();
}

fn benchmark_add_admin(c: &mut Criterion) {
    let mut group = c.benchmark_group("add-admin_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));


    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for n_admins in vec![10, 50, 100, 150, 200] {
        for n_users in vec![100, 400, 700, 1000] {
            let mut state: SumacState = filling_sumac_group(n_admins, n_users);
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

                            let username_new_admin = format!("Admin_{}", n_admins);

                            let t0 = Instant::now();
                            let _ = black_box(add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_new_admin,
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

                            let username_new_admin = format!("Admin_{}", n_admins);

                            let (commit_broadcast, _, _, _) = add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_new_admin,
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

                            let username_new_admin = format!("Admin_{}", n_admins);

                            let (_, _, _, encrypted_group_key) = add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_new_admin,
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

                            let username_new_admin = format!("Admin_{}", n_admins);

                            let (commit_broadcast, commit_unicast, encrypted_tree, _) =
                                add_admin_sumac_committer(
                                    &mut local_state,
                                    &provider,
                                    ciphersuite,
                                    &username_committer,
                                    &username_new_admin,
                                );

                            let t0 = Instant::now();
                            let _ = black_box(add_admin_sumac_new_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                commit_broadcast,
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
}

fn update_user_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_updated_user: &String,
) -> (
    CommitTMKABroadcast,
    Option<CommitTMKAUnicast>,
    HashMap<String, EncryptedCombinedPath>,
    LeafNodeIndex,
    AeadCiphertext,
) {
    let user_to_update = state.all_users.get(username_updated_user).unwrap();
    op_user_committer(
        &Operation::Update(user_to_update.clone()),
        provider,
        ciphersuite,
        state,
        &username_committer,
    )
    .unwrap()
}

fn update_user_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_to_update: &String,
    username_target_admin: &String,
    encrypted_group_key: AeadCiphertext,
    encrypted_regeneration_set: &EncryptedRegenerationSetHPKE,
) {
    let current_admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();
    let current_admin = state.all_admins.get_mut(username_target_admin).unwrap();
    let updated_user = state.all_users.get(username_to_update).unwrap();

    op_user_one_other_admin(
        &Operation::Update(updated_user.clone()),
        provider,
        ciphersuite,
        current_admin,
        current_admin_group,
        encrypted_group_key,
        encrypted_regeneration_set,
    )
    .unwrap();
}

fn update_user_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    username_to_update: &String,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_updated_user: &LeafNodeIndex,
) {
    let user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    let updated_user = state.all_users.get(username_to_update).unwrap();

    op_user_one_standard_user(
        &Operation::Update(updated_user.clone()),
        provider,
        ciphersuite,
        user_group,
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
    commit_unicast: Option<CommitTMKAUnicast>,
    username_committer: &String,
    username_updated_user: &String,
    leaf_index_updated_user: &LeafNodeIndex,
    welcome_new_user: Option<WelcomeNewUser>,
) {
    let updated_user = state.all_users.get(username_updated_user).unwrap();

    op_user_target_user(
        &Operation::Update(updated_user.clone()),
        provider,
        ciphersuite,
        state,
        username_committer,
        &username_updated_user,
        commit_unicast,
        welcome_new_user,
        leaf_index_updated_user,
    )
    .unwrap();
}
fn benchmark_update_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("update-user_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));


    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    // for n_admins in vec![10, 50, 100, 150, 200] {
    for n_admins in vec![10] {
        for n_users in vec![100, 400, 700, 1000] {
            let state: SumacState = filling_sumac_group(n_admins, n_users);

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

                            let (_, _, encrypted_regeneration_sets, _, encrypted_group_key) =
                                update_user_sumac_committer(
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

                            let (commit_broadcast, _, _, leaf_index, _) =
                                update_user_sumac_committer(
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
                                &username_to_update,
                                commit_broadcast,
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
                            let user_to_update = local_state
                                .all_users
                                .get(&username_to_update)
                                .unwrap()
                                .clone();

                            let (
                                _cb,
                                commit_unicast,
                                encrypted_rengeneration_sets,
                                leaf_index,
                                encrypted_group_key,
                            ) = update_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_to_update,
                            );

                            let welcome = op_user_other_admins(
                                &Operation::Update(user_to_update),
                                &provider,
                                ciphersuite,
                                &mut local_state,
                                &username_committer,
                                encrypted_group_key,
                                &encrypted_rengeneration_sets,
                            )
                            .unwrap();

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
                                welcome,
                            ));
                            total += t0.elapsed();
                        }
                        total
                    })
                },
            );
        }
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
    Option<CommitTMKAUnicast>,
    HashMap<String, EncryptedRegenerationSetHPKE>,
    LeafNodeIndex,
    AeadCiphertext,
) {
    let user_to_remove = state.all_users.get(username_removed_user).unwrap();
    op_user_committer(
        &Operation::Remove(user_to_remove.clone()),
        provider,
        ciphersuite,
        state,
        &username_committer,
    )
    .unwrap()
}

fn remove_user_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target_admin: &String,
    username_to_remove: &String,
    encrypted_group_key: AeadCiphertext,
    encrypted_regeneration_set: &EncryptedRegenerationSetHPKE,
) {
    let current_admin = state.all_admins.get(username_target_admin).unwrap();
    let admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();
    let user_to_remove = state.all_users.get(username_to_remove).unwrap();
    op_user_one_other_admin(
        &Operation::Remove(user_to_remove.clone()),
        provider,
        ciphersuite,
        current_admin,
        admin_group,
        encrypted_group_key,
        encrypted_regeneration_set,
    )
    .unwrap();
}

fn remove_user_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    username_to_remove: &String,
    commit_broadcast_tmka: CommitTMKABroadcast,
    leaf_index_removed_user: &LeafNodeIndex,
) {
    let user_to_remove = state.all_users.get(username_to_remove).unwrap();
    let mut user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    op_user_one_standard_user(
        &Operation::Remove(user_to_remove.clone()),
        provider,
        ciphersuite,
        &mut user_group,
        username_committer,
        commit_broadcast_tmka,
        leaf_index_removed_user,
    )
    .unwrap()
}

fn benchmark_remove_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove-user_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));


    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    // for n_admins in vec![10, 50, 100, 150, 200] {
        for n_admins in vec![10] {
        for n_users in vec![100, 400, 700, 1000] {
            let state: SumacState = filling_sumac_group(n_admins, n_users);

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

                            let (_cb, _, encrypted_regeneration_sets, _, encrypted_group_key) =
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
                                &username_target_admin,
                                &username_to_remove,
                                encrypted_group_key,
                                &encrypted_regeneration_sets
                                    .get(&username_target_admin)
                                    .unwrap(),
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

                            let (commit_broadcast, _, _ers, leaf_index, _) =
                                remove_user_sumac_committer(
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
                                &username_to_remove,
                                commit_broadcast,
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
}

fn remove_admin_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_removed_admin: &String,
) -> (
    CommitCGKABroadcast,
    Option<CommitCGKAUnicast>,
    Option<EncryptedRegenerationTree>,
    AeadCiphertext,
) {
    let removed_admin = state.all_admins.get(username_removed_admin).unwrap();

    op_admin_committer(
        &Operation::Remove(removed_admin.clone()),
        provider,
        ciphersuite,
        state,
        username_committer,
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
    let admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();
    op_admin_one_other_admin(provider, ciphersuite, admin_group, &commit_broadcast).unwrap()
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
    let admin_to_remove = state.all_admins.get(username_removed_admin).unwrap();
    op_admin_one_standard_user(
        &Operation::Remove(admin_to_remove.clone()),
        provider,
        ciphersuite,
        user_group,
        &encrypted_group_key,
        username_committer,
    )
    .unwrap()
}

fn benchmark_remove_admin(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove-admin_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));


    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for n_admins in vec![10, 50, 100, 150, 200] {
        for n_users in vec![100, 400, 700, 1000] {
            let state: SumacState = filling_sumac_group(n_admins, n_users);

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

                            let (commit_broadcast, _, _, _) = remove_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
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

                            let (_, _, _, encrypted_group_key) = remove_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
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
                                encrypted_group_key,
                            ));
                            total += t0.elapsed();
                        }
                        total
                    })
                },
            );
        }
    }
}

fn update_admin_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_updated_admin: &String,
) -> (
    CommitCGKABroadcast,
    Option<CommitCGKAUnicast>,
    Option<EncryptedRegenerationTree>,
    AeadCiphertext,
) {
    let updated_admin = state.all_admins.get(username_updated_admin).unwrap();
    op_admin_committer(
        &Operation::Update(updated_admin.clone()),
        provider,
        ciphersuite,
        state,
        username_committer,
    )
    .unwrap()
}

fn update_admin_sumac_one_other_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast: CommitCGKABroadcast,
    username_target_admin: &String,
) {
    let admin_group = state
        .all_admin_groups
        .get_mut(username_target_admin)
        .unwrap();

    op_admin_one_other_admin(provider, ciphersuite, admin_group, &commit_broadcast).unwrap()
}

fn update_admin_sumac_one_standard_user(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_target_user: &String,
    encrypted_group_key: AeadCiphertext,
    username_updated_admin: &String,
) {
    let user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    let updated_admin = state.all_admins.get(username_updated_admin).unwrap();
    op_admin_one_standard_user(
        &Operation::Update(updated_admin.clone()),
        provider,
        ciphersuite,
        user_group,
        &encrypted_group_key,
        username_committer,
    )
    .unwrap()
}

fn update_admin_sumac_updated_admin(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit_broadcast: CommitCGKABroadcast,
    commit_unicast: Option<CommitCGKAUnicast>,
    encrypted_tree: Option<EncryptedRegenerationTree>,
    username_updated_admin: &String,
) {
    let updated_admin = state.all_admins.get(username_updated_admin).unwrap();

    op_admin_target_admin(
        &Operation::Update(updated_admin.clone()),
        provider,
        ciphersuite,
        state,
        commit_broadcast,
        commit_unicast,
        encrypted_tree,
    )
    .unwrap();
}

fn benchmark_update_admin(c: &mut Criterion) {
    let mut group = c.benchmark_group("update-admin_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));


    let mut rng: ThreadRng = rng();
    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for n_admins in vec![10, 50, 100, 150, 200] {
        for n_users in vec![100, 400, 700, 1000] {
            let state: SumacState = filling_sumac_group(n_admins, n_users);

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

                            let username_updated_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|username| **username != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            let t0 = Instant::now();
                            let _ = black_box(update_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_updated_admin,
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

                            let username_updated_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|username| **username != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            let (commit_broadcast, _, _, _) = update_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_updated_admin,
                            );

                            let target_admin: String = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|candidate| {
                                    (**candidate != username_committer)
                                        && (**candidate != username_updated_admin)
                                })
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            let t0 = Instant::now();
                            let _ = black_box(update_admin_sumac_one_other_admin(
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

                            let username_updated_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|username| **username != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            let (_, _, _, encrypted_group_key) = update_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &username_updated_admin,
                            );

                            let target_user: String = local_state
                                .all_user_groups
                                .keys()
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            let t0 = Instant::now();
                            let _ = black_box(update_admin_sumac_one_standard_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                &username_committer,
                                &target_user,
                                encrypted_group_key,
                                &username_updated_admin,
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

                            let username_updated_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|username| **username != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            let (commit_broadcast, commit_unicast, encrypted_tree, _) =
                                add_admin_sumac_committer(
                                    &mut local_state,
                                    &provider,
                                    ciphersuite,
                                    &username_committer,
                                    &username_updated_admin,
                                );

                            let t0 = Instant::now();
                            let _ = black_box(update_admin_sumac_updated_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                commit_broadcast,
                                commit_unicast,
                                encrypted_tree,
                                &username_updated_admin,
                            ));
                            total += t0.elapsed();
                        }
                        total
                    })
                },
            );
        }
    }
}

criterion_group!(
    bench_sumac,
    benchmark_remove_admin,
    benchmark_add_admin,
    benchmark_update_admin,
    benchmark_add_user,
    benchmark_update_user,
    benchmark_remove_user,
);
criterion_main!(bench_sumac);
