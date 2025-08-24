use std::collections::HashMap;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use openmls::prelude::Ciphersuite;
use openmls::storage::OpenMlsProvider;
use openmls_rust_crypto::OpenMlsRustCrypto;

use rand::{rng, thread_rng};
use rand::rngs::ThreadRng;
use rand::seq::IteratorRandom;
use sumac_rs::cgka::{CGKAGroup, CommitCGKABroadcast, CommitCGKAUnicast};
use sumac_rs::test_utils::{create_pool_of_users, create_user, setup_provider, CIPHERSUITE};
use sumac_rs::user::User;
use sumac_rs::{user, Operation};

#[derive(Clone)]
struct CGKAState {
    pub all_groups: HashMap<String, CGKAGroup>,
    pub all_users: HashMap<String, User>,
}

fn filling_cgka_group(
    n_users: usize,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> CGKAState {
    let all_users = create_pool_of_users(n_users, provider, "User".to_string());

    let all_groups =
        CGKAGroup::generate_random_group(provider, ciphersuite, &all_users, "User".to_string())
            .unwrap();

    CGKAState {
        all_groups,
        all_users,
    }
}

fn add_user_cgka_committer(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_new_user: &String,
) {
    let new_user = state.all_users.get(username_new_user).unwrap().clone();

    state
        .all_groups
        .get_mut(username_committer)
        .unwrap()
        .commit(Operation::Add(new_user), ciphersuite, provider)
        .unwrap();
}

fn add_user_cgka_one_other(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target: &String,
    commit: CommitCGKABroadcast,
) {
    let target_group = state.all_groups.get_mut(username_target).unwrap();

    target_group
        .process(&commit, provider, ciphersuite)
        .unwrap()
}

fn add_user_cgka_new_user(
    _state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit: CommitCGKAUnicast,
    new_user: &User,
) {
    CGKAGroup::process_welcome(commit, provider, ciphersuite, new_user).unwrap();
}

fn benchmark_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("add-user_cgka");
    // Control the number of measurements (samples)
    group.sample_size(10); // Default is 100, lower for faster benches
                           // Control total measurement time
    group.measurement_time(Duration::from_secs(10)); // Default is 5s
    group.warm_up_time(Duration::from_nanos(1));

    let ciphersuite = CIPHERSUITE;
    let provider = setup_provider();
    let mut rng: ThreadRng = rng();

    for &n_users in &[10, 100, 1000] {
        let mut state = filling_cgka_group(n_users, &provider, ciphersuite);
        let new_user_name = format!("User_{}", n_users);
        let new_user = create_user(new_user_name.clone(), &provider);
        state
            .all_users
            .insert(new_user_name.clone(), new_user.clone());

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in (0..iters) {
                        let mut local_state = state.clone();
                        let username_committer = state.all_groups.keys().choose(&mut rng).unwrap();

                        let start = Instant::now();

                        black_box(add_user_cgka_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            username_committer,
                            &new_user_name,
                        ));

                        let stop = start.elapsed();
                        total += stop;
                    }
                    total
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();
                        let target_username = local_state
                            .all_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_committer = local_state
                            .all_groups
                            .keys()
                            .filter(|candidate| **candidate != target_username)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _) = local_state
                            .all_groups
                            .get_mut(&username_committer)
                            .unwrap()
                            .commit(Operation::Add(new_user.clone()), ciphersuite, &provider)
                            .unwrap();

                        let start = Instant::now();
                        black_box(add_user_cgka_one_other(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &target_username,
                            commit_broadcast,
                        ));
                        let stop = start.elapsed();
                        total += stop;
                    }
                    total
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("New User - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut local_state = state.clone();

                        let username_committer = local_state
                            .all_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let (_, commit_unicast) = local_state
                            .all_groups
                            .get_mut(&username_committer)
                            .unwrap()
                            .commit(Operation::Add(new_user.clone()), ciphersuite, &provider)
                            .unwrap();

                        let start = Instant::now();
                        black_box(add_user_cgka_new_user(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            commit_unicast.unwrap(),
                            &new_user,
                        ));
                        let stop = start.elapsed();
                        total += stop;
                        // Function under test
                    }
                    total
                })
            },
        );
    }

    group.finish();
}

fn remove_user_cgka_committer(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
    username_to_delete: &String,
) {
    let user_to_delete = state.all_users.get(username_to_delete).unwrap().clone();

    state
        .all_groups
        .get_mut(username_committer)
        .unwrap()
        .commit(Operation::Remove(user_to_delete), ciphersuite, provider)
        .unwrap();
}

fn remove_user_cgka_one_other(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target: &String,
    commit: CommitCGKABroadcast,
) {
    let target_group = state.all_groups.get_mut(username_target).unwrap();

    target_group
        .process(&commit, provider, ciphersuite)
        .unwrap()
}

fn benchmark_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove-user_cgka");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_nanos(1));

    let ciphersuite = CIPHERSUITE;
    let provider = setup_provider();
    let mut rng: ThreadRng = thread_rng();

    for &n_users in &[10, 100, 1000] {
        let state = filling_cgka_group(n_users, &provider, ciphersuite);

        // -------- Committer path: measure ONLY core op --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer - {}", n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // ---- setup (NOT TIMED) ----
                        let mut local_state = state.clone();
                        // choose distinct committer and user to delete (OWNED to avoid borrows)
                        let username_committer: String = local_state
                            .all_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_delete: String = local_state
                            .all_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        // ---- timed section: ONLY the core op ----
                        let t0 = Instant::now();
                        let _ = black_box(remove_user_cgka_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                            &username_to_delete,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other member path: measure ONLY core op --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other - {}", n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // ---- setup (NOT TIMED) ----
                        let mut local_state = state.clone();

                        // choose distinct users (OWNED Strings)
                        let username_committer: String = local_state
                            .all_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let username_to_delete: String = local_state
                            .all_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let target_user: String = local_state
                            .all_groups
                            .keys()
                            .filter(|candidate| {
                                **candidate != username_committer && **candidate != username_to_delete
                            })
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        // build the commit to be applied by "other"
                        let user_to_delete = local_state
                            .all_users
                            .get(&username_to_delete)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _) = local_state
                            .all_groups
                            .get_mut(&username_committer)
                            .unwrap()
                            .commit(
                                Operation::Remove(user_to_delete),
                                ciphersuite,
                                &provider,
                            )
                            .unwrap();

                        // ---- timed section: ONLY the core op ----
                        let t0 = Instant::now();
                        let _ = black_box(remove_user_cgka_one_other(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &target_user,
                            commit_broadcast,
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



fn update_user_cgka_committer(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer: &String,
) {
    let user_committer: User = state.all_users.get(username_committer).unwrap().clone();

    state
        .all_groups
        .get_mut(username_committer)
        .unwrap()
        .commit(Operation::Update(user_committer), ciphersuite, provider)
        .unwrap();
}

fn update_user_cgka_one_other(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target: &String,
    commit: CommitCGKABroadcast,
) {
    let target_group = state.all_groups.get_mut(username_target).unwrap();

    target_group
        .process(&commit, provider, ciphersuite)
        .unwrap()
}

fn benchmark_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("update-user_cgka");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_nanos(1));

    let ciphersuite = CIPHERSUITE;
    let provider = setup_provider();
    let mut rng: ThreadRng = thread_rng();

    for &n_users in &[10, 100, 1000] {
        let state = filling_cgka_group(n_users, &provider, ciphersuite);

        // -------- Committer path: measure ONLY core op --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer - {}", n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // ---- setup (NOT TIMED) ----
                        let mut local_state = state.clone();
                        let username_committer: String = local_state
                            .all_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        // ---- timed section: ONLY the core op ----
                        let t0 = Instant::now();
                        let _ = black_box(update_user_cgka_committer(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &username_committer,
                        ));
                        total += t0.elapsed();
                    }
                    total
                })
            },
        );

        // -------- Other member path: measure ONLY core op --------
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other - {}", n_users)),
            &n_users,
            |b, &_n| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // ---- setup (NOT TIMED) ----
                        let mut local_state = state.clone();

                        let username_committer: String = local_state
                            .all_groups
                            .keys()
                            .choose(&mut rng)
                            .unwrap()
                            .clone();
                        let target_user: String = local_state
                            .all_groups
                            .keys()
                            .filter(|candidate| **candidate != username_committer)
                            .choose(&mut rng)
                            .unwrap()
                            .clone();

                        let committer_user = local_state
                            .all_users
                            .get(&username_committer)
                            .unwrap()
                            .clone();

                        let (commit_broadcast, _) = local_state
                            .all_groups
                            .get_mut(&username_committer)
                            .unwrap()
                            .commit(
                                Operation::Update(committer_user),
                                ciphersuite,
                                &provider,
                            )
                            .unwrap();

                        // ---- timed section: ONLY the core op ----
                        let t0 = Instant::now();
                        let _ = black_box(update_user_cgka_one_other(
                            &mut local_state,
                            &provider,
                            ciphersuite,
                            &target_user,
                            commit_broadcast,
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
criterion_group!(
    bench_cgka,
    benchmark_add,
    benchmark_remove,
    benchmark_update
);
criterion_main!(bench_cgka);
