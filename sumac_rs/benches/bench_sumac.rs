use std::{collections::HashMap, time::Duration};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use openmls::{
    prelude::{Ciphersuite, Credential, HpkeCiphertext, LeafNodeIndex, ParentNodeIndex},
    tree_sumac::{OptionLeafNodeTMKA, OptionParentNodeTMKA, SumacTree},
};
use openmls_traits::OpenMlsProvider;
use rand::{rng, rngs::ThreadRng, seq::IteratorRandom};
use sumac_rs::{
    cgka::{CommitCGKABroadcast, CommitCGKAUnicast},
    sumac::{
        create_large_sumac_group,
        regeneration::{
            EncryptedCombinedPath, EncryptedRegenerationSet, EncryptedRegenerationTree,
            RegenerationTree,
        },
        setup_sumac,
        sumac_operations::{
            add_admin::{
                add_admin_committer, add_admin_new_admin, add_admin_only_one_other_admin,
                add_admin_only_one_standard_user,
            }, add_user::{
                add_user_committer, add_user_new_user, add_user_one_other_admin,
                add_user_one_standard_user, add_user_other_admins,
            }, remove_user::{remove_user_committer, remove_user_only_one_other_admin, remove_user_only_one_user}, update_user::{
                update_user_committer, update_user_only_one_other_admin,
                update_user_only_one_other_user, update_user_target_user,
            }
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

fn add_user_sumac_committer(
    state: &mut SumacState,
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    n_users: usize,
    username_committer: &String,
) -> (
    CommitTMKABroadcast,
    CommitTMKAUnicast,
    EncryptedRegenerationSet,
    LeafNodeIndex,
) {
    add_user_committer(
        provider,
        ciphersuite,
        &mut state.all_users,
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
    encrypted_regeneration_set: &EncryptedRegenerationSet,
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
        &state.all_users,
        target_admin_group,
        new_user,
        &committer,
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
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng = rng();

    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for &n_admins in &[2, 5, 10] {
        for &n_users in &[10, 100, 1000] {
            let mut state: SumacState = filling_sumac_group(n_admins, n_users);
            // add an user to add
            let new_user_name = format!("User_{}", n_users);
            let new_user = create_user(new_user_name.clone(), &provider);
            state.all_users.insert(new_user_name.clone(), new_user);

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            (
                                state.clone(),
                                state.all_admin_groups.keys().choose(&mut rng).unwrap(),
                            )
                        },
                        |(mut local_state, username_committer)| {
                            black_box(add_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_users,
                                username_committer,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Other_Admin:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer = local_state
                                .all_admin_groups
                                .keys()
                                .choose(&mut rng)
                                .unwrap()
                                .clone();
                            let (_, _, encrypted_regeneration_set, _) = add_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_users,
                                &username_committer,
                            );

                            let target_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|candidate| **candidate != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            (
                                local_state,
                                username_committer,
                                encrypted_regeneration_set,
                                target_admin,
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            encrypted_regeneration_set,
                            target_admin,
                        )| {
                            black_box(add_user_sumac_one_other_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_users,
                                &encrypted_regeneration_set,
                                &username_committer,
                                &target_admin,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Standard Users:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();

                            let (commit_broadcast, _, _, leaf_index_new_user) =
                                add_user_sumac_committer(
                                    &mut local_state,
                                    &provider,
                                    ciphersuite,
                                    n_users,
                                    username_committer,
                                );

                            let target_user =
                                state.all_user_groups.keys().choose(&mut rng).unwrap();

                            (
                                local_state,
                                username_committer,
                                commit_broadcast,
                                target_user,
                                leaf_index_new_user,
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            commit_broadcast,
                            target_user,
                            leaf_index_new_user,
                        )| {
                            black_box(add_user_sumac_one_standard_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                commit_broadcast,
                                &leaf_index_new_user,
                                username_committer,
                                target_user,
                            ));
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("New User:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();

                            let (
                                _,
                                commit_unicast,
                                encrypted_regeneration_set,
                                leaf_index_new_user,
                            ) = add_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_users,
                                username_committer,
                            );

                            let welcome_new_user = add_user_other_admins(
                                &provider,
                                ciphersuite,
                                &state.all_admins,
                                &state.all_users,
                                &mut local_state.all_admin_groups,
                                &new_user_name,
                                &username_committer,
                                &encrypted_regeneration_set,
                            )
                            .unwrap();

                            (
                                local_state,
                                username_committer,
                                commit_unicast,
                                leaf_index_new_user,
                                welcome_new_user,
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            commit_unicast,
                            leaf_index_new_user,
                            welcome_new_user,
                        )| {
                            black_box(add_user_sumac_new_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                new_user_name.clone(),
                                username_committer.to_string(),
                                commit_unicast,
                                welcome_new_user,
                                &leaf_index_new_user,
                            ));
                        },
                        criterion::BatchSize::LargeInput,
                    )
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
    n_admins: usize,
    username_committer: &String,
) -> (
    CommitCGKABroadcast,
    CommitCGKAUnicast,
    EncryptedRegenerationTree,
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
) {
    let user_group = state.all_user_groups.get_mut(username_target_user).unwrap();
    add_admin_only_one_standard_user(provider, ciphersuite, user_group, username_committer).unwrap()
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
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();

    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for &n_admins in &[2, 5, 10] {
        for &n_users in &[10, 100, 1000] {
            let mut state: SumacState = filling_sumac_group(n_admins, n_users);
            // add an admin to add
            let new_admin_name = format!("Admin_{}", n_admins);
            let new_admin = create_user(new_admin_name.clone(), &provider);
            state.all_admins.insert(new_admin_name.clone(), new_admin);

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            (
                                state.clone(),
                                state.all_admin_groups.keys().choose(&mut rng).unwrap(),
                            )
                        },
                        |(mut local_state, username_committer)| {
                            black_box(add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_admins,
                                username_committer,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let (commit_broadcast, _, _) = add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_admins,
                                username_committer,
                            );

                            let target_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|candidate| *candidate != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            (local_state, commit_broadcast, target_admin)
                        },
                        |(mut local_state, commit_broadcast, target_admin)| {
                            black_box(add_admin_sumac_one_other_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                commit_broadcast,
                                &target_admin,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let (_, _, _) = add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_admins,
                                username_committer,
                            );

                            let target_user = local_state
                                .all_user_groups
                                .keys()
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            (local_state, target_user, username_committer)
                        },
                        |(mut local_state, target_user, username_committer)| {
                            black_box(add_admin_sumac_one_standard_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                &target_user,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("New Admin:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let (_, commit_unicast, encrypted_tree) = add_admin_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                n_admins,
                                username_committer,
                            );

                            (local_state, commit_unicast, encrypted_tree)
                        },
                        |(mut local_state, commit_unicast, encrypted_tree)| {
                            black_box(add_admin_sumac_new_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                commit_unicast,
                                encrypted_tree,
                                &new_admin_name,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
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
    CommitTMKAUnicast,
    EncryptedRegenerationSet,
    LeafNodeIndex,
) {
    println!("Updating {username_updated_user}");
    update_user_committer(
        provider,
        ciphersuite,
        &mut state.all_users,
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
    encrypted_regeneration_set: &EncryptedRegenerationSet,
) {
    update_user_only_one_other_admin(
        provider,
        ciphersuite,
        &state.all_users,
        &mut state.all_admin_groups,
        username_to_update,
        username_committer,
        username_target_admin,
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
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();

    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for &n_admins in &[2, 5, 10] {
        for &n_users in &[10, 100, 1000] {
            let mut state: SumacState = filling_sumac_group(n_admins, n_users);

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            (
                                state.clone(),
                                state.all_admin_groups.keys().choose(&mut rng).unwrap(),
                                state.all_user_groups.keys().choose(&mut rng).unwrap(),
                            )
                        },
                        |(mut local_state, username_committer, username_updated_user)| {
                            black_box(update_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                username_updated_user,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let username_to_update =
                                state.all_user_groups.keys().choose(&mut rng).unwrap();

                            let (commit_broadcast, _, encrypted_regeneration_set, _) =
                                update_user_sumac_committer(
                                    &mut local_state,
                                    &provider,
                                    ciphersuite,
                                    username_committer,
                                    username_to_update,
                                );

                            let username_target_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|candidate| *candidate != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            (
                                local_state,
                                commit_broadcast,
                                username_to_update,
                                username_committer,
                                username_target_admin,
                                encrypted_regeneration_set,
                            )
                        },
                        |(
                            mut local_state,
                            commit_broadcast,
                            username_to_update,
                            username_committer,
                            username_target_admin,
                            encrypted_regeneration_set,
                        )| {
                            black_box(update_user_sumac_one_other_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_to_update,
                                username_committer,
                                &username_target_admin,
                                &encrypted_regeneration_set,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let username_to_update =
                                state.all_user_groups.keys().choose(&mut rng).unwrap();
                            let username_target_user = state
                                .all_user_groups
                                .keys()
                                .filter(|username| *username != username_to_update)
                                .choose(&mut rng)
                                .unwrap();

                            let (commit_broadcast, _, _, leaf_index) = update_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                username_to_update,
                            );

                            (
                                local_state,
                                username_committer,
                                username_target_user,
                                commit_broadcast,
                                leaf_index,
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            username_target_user,
                            commit_broadcast_tmka,
                            leaf_index_updated_user,
                        )| {
                            black_box(update_user_sumac_one_standard_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                &username_target_user,
                                &commit_broadcast_tmka,
                                &leaf_index_updated_user,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Target User:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let username_to_update =
                                state.all_user_groups.keys().choose(&mut rng).unwrap();

                            let (_, commit_unicast, _, leaf_index) = update_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                username_to_update,
                            );

                            (
                                local_state,
                                username_committer,
                                username_to_update,
                                commit_unicast,
                                leaf_index,
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            username_to_update,
                            commit_unicast_tmka,
                            leaf_index_updated_user,
                        )| {
                            black_box(update_user_sumac_updated_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                commit_unicast_tmka,
                                username_committer,
                                &username_to_update,
                                &leaf_index_updated_user,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
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
    EncryptedRegenerationSet,
    LeafNodeIndex,
) {
    remove_user_committer(
        provider,
        ciphersuite,
        &mut state.all_users,
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
    encrypted_regeneration_set: &EncryptedRegenerationSet,
    leaf_index_to_remove : &LeafNodeIndex
) {
    remove_user_only_one_other_admin(
        provider,
        ciphersuite,
        &mut state.all_admin_groups,
        username_committer,
        username_target_admin,
        encrypted_regeneration_set,
        leaf_index_to_remove
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
        username_target_user
    )
    .unwrap()
}



fn benchmark_remove_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove-user_sumac");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_nanos(1));

    let mut rng: ThreadRng = rng();

    let provider = setup_provider();
    let ciphersuite = CIPHERSUITE;

    for &n_admins in &[2, 5, 10] {
        for &n_users in &[10, 100, 1000] {
            let mut state: SumacState = filling_sumac_group(n_admins, n_users);

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Committer:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            (
                                state.clone(),
                                state.all_admin_groups.keys().choose(&mut rng).unwrap(),
                                state.all_user_groups.keys().choose(&mut rng).unwrap(),
                            )
                        },
                        |(mut local_state, username_committer, username_removed_user)| {
                            black_box(remove_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                username_removed_user,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Other Admin:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let username_to_remove =
                                state.all_user_groups.keys().choose(&mut rng).unwrap();

                            let (_, encrypted_regeneration_set, leaf_index) =
                                remove_user_sumac_committer(
                                    &mut local_state,
                                    &provider,
                                    ciphersuite,
                                    username_committer,
                                    username_to_remove,
                                );

                            let username_target_admin = local_state
                                .all_admin_groups
                                .keys()
                                .filter(|candidate| *candidate != username_committer)
                                .choose(&mut rng)
                                .unwrap()
                                .clone();

                            (
                                local_state,
                                username_committer,
                                username_target_admin,
                                encrypted_regeneration_set,
                                leaf_index
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            username_target_admin,
                            encrypted_regeneration_set,
                            leaf_index
                        )| {
                            black_box(remove_user_sumac_one_other_admin(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                &username_target_admin,
                                &encrypted_regeneration_set,
                                &leaf_index
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );

            group.bench_with_input(
                BenchmarkId::from_parameter(format!("Standard User:{}-{}", n_admins, n_users)),
                &n_users,
                |b, &n_users| {
                    b.iter_batched(
                        || {
                            let mut local_state = state.clone();
                            let username_committer =
                                state.all_admin_groups.keys().choose(&mut rng).unwrap();
                            let username_to_remove =
                                state.all_user_groups.keys().choose(&mut rng).unwrap();
                            let username_target_user = state
                                .all_user_groups
                                .keys()
                                .filter(|username| *username != username_to_remove)
                                .choose(&mut rng)
                                .unwrap();

                            let (commit_broadcast, _, leaf_index) = remove_user_sumac_committer(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                username_to_remove,
                            );

                            (
                                local_state,
                                username_committer,
                                username_target_user,
                                commit_broadcast,
                                leaf_index,
                            )
                        },
                        |(
                            mut local_state,
                            username_committer,
                            username_target_user,
                            commit_broadcast_tmka,
                            leaf_index_removed_user,
                        )| {
                            black_box(remove_user_sumac_one_standard_user(
                                &mut local_state,
                                &provider,
                                ciphersuite,
                                username_committer,
                                &username_target_user,
                                &commit_broadcast_tmka,
                                &leaf_index_removed_user,
                            ))
                        },
                        criterion::BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}


criterion_group!(bench_sumac, /*benchmark_add_admin, benchmark_add_user, benchmark_update_user, */benchmark_remove_user);
criterion_main!(bench_sumac);
