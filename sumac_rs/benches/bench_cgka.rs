use std::collections::HashMap;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use openmls::prelude::Ciphersuite;
use openmls::storage::OpenMlsProvider;
use openmls_rust_crypto::OpenMlsRustCrypto;

use rand::rng;
use rand::rngs::ThreadRng;
use rand::seq::IteratorRandom;
use sumac_rs::cgka::{CGKAGroup, CommitCGKABroadcast, CommitCGKAUnicast};
use sumac_rs::test_utils::{create_pool_of_users, create_user, setup_provider, CIPHERSUITE};
use sumac_rs::{user, Operation};
use sumac_rs::user::User;

#[derive(Clone)]
struct CGKAState {
    pub all_groups: HashMap<String,CGKAGroup>,
    pub all_users: HashMap<String, User>,
}


fn filling_cgka_group(
    n_users: usize,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
) -> CGKAState {
    let all_users = create_pool_of_users(n_users, provider, "User".to_string());

    let all_groups = CGKAGroup::generate_random_group(provider, ciphersuite, &all_users, "User".to_string()).unwrap();

    CGKAState { all_groups, all_users  }
}



fn add_user_cgka_committer(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer : &String,
    username_new_user : &String
) {
    let new_user = state.all_users.get(username_new_user).unwrap().clone();

    state
        .all_groups.get_mut(username_committer).unwrap()
        .commit(Operation::Add(new_user), ciphersuite, provider).unwrap();
}


fn add_user_cgka_one_other(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target : &String,
    commit : CommitCGKABroadcast
) {
    let target_group = state.all_groups.get_mut(username_target).unwrap();

    target_group.process(&commit, provider, ciphersuite).unwrap()
    
}



fn add_user_cgka_new_user(
    _state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    commit: CommitCGKAUnicast,
    new_user : &User
){
    CGKAGroup::process_welcome(commit, provider, ciphersuite, new_user).unwrap();
}




fn benchmark_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_user_cgka");
    // Control the number of measurements (samples)
    group.sample_size(10); // Default is 100, lower for faster benches
                           // Control total measurement time
    group.measurement_time(Duration::from_secs(60)); // Default is 5s
    group.warm_up_time(Duration::from_nanos(1));

    let ciphersuite = CIPHERSUITE;
    let provider = setup_provider();
    let mut rng: ThreadRng = rng();


    for &n_users in &[10, 100, 1000] {
        let mut state = filling_cgka_group(n_users, &provider, ciphersuite);
        let new_user_name = format!("User_{}", n_users);
        let new_user = create_user(new_user_name.clone(), &provider);
        state.all_users.insert(new_user_name.clone(), new_user.clone());

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        (state.clone(), state.all_groups.keys().choose(&mut rng).unwrap())
                    },
                    |(mut local_state, username_committer)| {
                        black_box(add_user_cgka_committer(&mut local_state, &provider, ciphersuite, username_committer, &new_user_name))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        let mut local_state = state.clone();
                        let target_username = local_state.all_groups.keys().choose(&mut rng).unwrap().clone();
                        let username_committer = local_state.all_groups.keys().filter(|candidate| **candidate != target_username).choose(&mut rng).unwrap().clone();


                        let (commit_broadcast, _) = local_state.all_groups.get_mut(&username_committer).unwrap().commit(Operation::Add(new_user.clone()), ciphersuite, &provider).unwrap();

                        (local_state, target_username.clone(), commit_broadcast)
                    },
                    |(mut local_state, target_user, commit)| {
                        black_box(add_user_cgka_one_other(&mut local_state, &provider, ciphersuite, &target_user, commit))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("New User - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        let mut local_state = state.clone();
                        
                        let username_committer = local_state.all_groups.keys().choose(&mut rng).unwrap().clone();


                        let (_, commit_unicast) = local_state.all_groups.get_mut(&username_committer).unwrap().commit(Operation::Add(new_user.clone()), ciphersuite, &provider).unwrap();

                        (local_state, commit_unicast)
                    },
                    |(mut local_state,  commit)| {
                        black_box(add_user_cgka_new_user(&mut local_state, &provider, ciphersuite, commit.unwrap(), &new_user))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}



fn remove_user_cgka_committer(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer : &String,
    username_to_delete : &String
) {
    let user_to_delete = state.all_users.get(username_to_delete).unwrap().clone();

    state
        .all_groups.get_mut(username_committer).unwrap()
        .commit(Operation::Remove(user_to_delete), ciphersuite, provider).unwrap();
}



fn remove_user_cgka_one_other(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target : &String,
    commit : CommitCGKABroadcast
) {
    let target_group = state.all_groups.get_mut(username_target).unwrap();

    target_group.process(&commit, provider, ciphersuite).unwrap()
    
}




fn benchmark_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove_user_cgka");
    // Control the number of measurements (samples)
    group.sample_size(10); // Default is 100, lower for faster benches
                           // Control total measurement time
    group.measurement_time(Duration::from_secs(60)); // Default is 5s
    group.warm_up_time(Duration::from_nanos(1));

    let ciphersuite = CIPHERSUITE;
    let provider = setup_provider();
    let mut rng: ThreadRng = rng();


    for &n_users in &[10, 100, 1000] {
        let mut state = filling_cgka_group(n_users, &provider, ciphersuite);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        let mut local_state = state.clone();

                        let username_committer = state.all_groups.keys().choose(&mut rng).unwrap();
                        let username_to_delete = state.all_groups.keys().filter(|candidate| *candidate != username_committer).choose(&mut rng).unwrap();

                        (local_state, username_committer, username_to_delete)

                    },
                    |(mut local_state, username_committer, username_to_delete)| {
                        black_box(remove_user_cgka_committer(&mut local_state, &provider, ciphersuite, username_committer, &username_to_delete))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        let mut local_state = state.clone();

                        let username_committer = state.all_groups.keys().choose(&mut rng).unwrap();
                        let username_to_delete = state.all_groups.keys().filter(|candidate| *candidate != username_committer).choose(&mut rng).unwrap();
                        let target_user = state.all_groups.keys().filter(|candidate| (*candidate != username_committer) && (*candidate != username_to_delete)).choose(&mut rng).unwrap();

                        let user_to_delete = local_state.all_users.get(username_to_delete).unwrap().clone();

                        let (commit_broadcast, _) = local_state.all_groups.get_mut(username_committer).unwrap().commit(Operation::Remove(user_to_delete), ciphersuite, &provider).unwrap();

                        (local_state, target_user, commit_broadcast)
                    },
                    |(mut local_state, target_user, commit)| {
                        black_box(remove_user_cgka_one_other(&mut local_state, &provider, ciphersuite, &target_user, commit))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

    }

    group.finish();
}



fn update_user_cgka_committer(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_committer : &String,
) {
    let user_committer: User = state.all_users.get(username_committer).unwrap().clone();

    state
        .all_groups.get_mut(username_committer).unwrap()
        .commit(Operation::Update(user_committer), ciphersuite, provider).unwrap();
}



fn update_user_cgka_one_other(
    state: &mut CGKAState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    username_target : &String,
    commit : CommitCGKABroadcast
) {
    let target_group = state.all_groups.get_mut(username_target).unwrap();

    target_group.process(&commit, provider, ciphersuite).unwrap()
    
}




fn benchmark_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_user_cgka");
    // Control the number of measurements (samples)
    group.sample_size(10); // Default is 100, lower for faster benches
                           // Control total measurement time
    group.measurement_time(Duration::from_secs(60)); // Default is 5s
    group.warm_up_time(Duration::from_nanos(1));

    let ciphersuite = CIPHERSUITE;
    let provider = setup_provider();
    let mut rng: ThreadRng = rng();


    for &n_users in &[10, 100, 1000] {
        let mut state = filling_cgka_group(n_users, &provider, ciphersuite);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Committer - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        let mut local_state = state.clone();

                        let username_committer = state.all_groups.keys().choose(&mut rng).unwrap();

                        (local_state, username_committer)

                    },
                    |(mut local_state, username_committer)| {
                        black_box(update_user_cgka_committer(&mut local_state, &provider, ciphersuite, username_committer))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Other - {}", n_users)),
            &n_users,
            |b, &n_users| {
                b.iter_batched(
                    || {
                        let mut local_state = state.clone();

                        let username_committer = state.all_groups.keys().choose(&mut rng).unwrap();
                        let target_user = state.all_groups.keys().filter(|candidate| *candidate != username_committer).choose(&mut rng).unwrap();

                        let committer = local_state.all_users.get(username_committer).unwrap().clone();

                        let (commit_broadcast, _) = local_state.all_groups.get_mut(username_committer).unwrap().commit(Operation::Update(committer), ciphersuite, &provider).unwrap();

                        (local_state, target_user, commit_broadcast)
                    },
                    |(mut local_state, target_user, commit)| {
                        black_box(update_user_cgka_one_other(&mut local_state, &provider, ciphersuite, &target_user, commit))
                        // Function under test
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

    }

    group.finish();
}


criterion_group!(bench_cgka, benchmark_add, benchmark_remove, benchmark_update);
criterion_main!(bench_cgka);
