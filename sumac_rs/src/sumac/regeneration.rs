use crate::{
    crypto::secret::Secret,
    errors::SumacError,
    tmka::{admin_group::TmkaAdminGroup, user_group::TmkaSlaveGroup, TreeTMKA},
};
use either::Either;
use openmls::{
    prelude::{
        Ciphersuite, HpkeCiphertext, LeafNodeIndex, OpenMlsCrypto, ParentNodeIndex, PathSecret,
    },
    storage::OpenMlsProvider,
    tree_sumac::{
        nodes::encryption_keys::{PkePrivateKey, PkePublicKey, SymmetricKey},
        LeafNodeTMKA, ParentNodeTMKA, RatchetTree,
    },
};
use openmls::{
    prelude::{Credential, Secret as MlsSecret},
    tree_sumac::NodeVariant,
};

///// This structure is only a path, so not usable for add-admin: TODO: faire l'équivalent en forme d'arbre (voir comment on peut le parcourr simplement)
pub struct RegenerationSet {
    leaf_index: LeafNodeIndex,
    leaf_secret: Option<Secret>,
    path_secrets: Vec<(ParentNodeIndex, PathSecret)>,
}

impl RegenerationSet {
    pub fn leaf_index(&self) -> LeafNodeIndex {
        self.leaf_index
    }

    pub fn secrets(&self) -> &[(ParentNodeIndex, PathSecret)] {
        &self.path_secrets
    }

    pub fn leaf_secret(&self) -> Option<&Secret> {
        self.leaf_secret.as_ref()
    }

    pub fn encrypt_symmetric(
        &self,
        crypto: &impl OpenMlsCrypto,
        key: &SymmetricKey,
    ) -> EncryptedRegenerationSet {
        let encrypted_secrets = self
            .path_secrets
            .iter()
            .map(|(index, path_secret)| {
                (
                    *index,
                    key.encrypt(crypto, path_secret.clone().secret().as_slice())
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let encrypted_leaf_secret = self
            .leaf_secret
            .as_ref()
            .map(|leaf_secret| key.encrypt(crypto, leaf_secret.as_slice()).unwrap());

        EncryptedRegenerationSet {
            leaf_index: self.leaf_index,
            leaf_secret: encrypted_leaf_secret,
            encrypted_path_secrets: encrypted_secrets,
        }
    }
}

pub struct EncryptedRegenerationSet {
    leaf_index: LeafNodeIndex,
    leaf_secret: Option<Vec<u8>>,
    encrypted_path_secrets: Vec<(ParentNodeIndex, Vec<u8>)>,
}

impl EncryptedRegenerationSet {
    pub fn decrypt_symmetric(
        &self,
        crypto: &impl OpenMlsCrypto,
        key: &SymmetricKey,
    ) -> RegenerationSet {
        let plain_secrets = self
            .encrypted_path_secrets
            .iter()
            .map(|(index, path_secret)| {
                (
                    *index,
                    PathSecret::from(MlsSecret::from_slice(
                        key.decrypt(crypto, path_secret).unwrap().as_slice(),
                    )),
                )
            })
            .collect();

        let leaf_secret = self.leaf_secret.as_ref().map(|leaf_secret| {
            Secret::from_slice(key.decrypt(crypto, leaf_secret).unwrap().as_slice())
        });

        RegenerationSet {
            leaf_index: self.leaf_index,
            leaf_secret,
            path_secrets: plain_secrets,
        }
    }
}

pub type CombinedPath = RegenerationSet;

pub struct EncryptedCombinedPath {
    pub leaf_node_index: LeafNodeIndex,
    pub indexes: Vec<ParentNodeIndex>,
    pub ciphertext: HpkeCiphertext,
    pub with_leaf: bool,
}
pub type EncryptedRegenerationSetHPKE = EncryptedCombinedPath;

impl CombinedPath {
    pub fn encrypt_hpke(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        encryption_key: &PkePublicKey,
    ) -> Result<EncryptedCombinedPath, SumacError> {
        let mut byte_stream_vec = Vec::new();
        let mut indexes = Vec::new();
        // start by appending the leaf secret
        let with_leaf = if let Some(leaf_secret) = self.leaf_secret() {
            byte_stream_vec.push(leaf_secret.clone().as_slice().to_vec());
            true
        } else {
            false
        };
        let path_secrets = self.path_secrets.clone();
        for (index, secret) in path_secrets.into_iter() {
            let binding = secret.clone().secret();
            byte_stream_vec.push(binding.as_slice().to_vec());
            indexes.push(index);
        }

        let ciphertext = encryption_key
            .encrypt(provider.crypto(), ciphersuite, &byte_stream_vec.concat())
            .expect("Encryption failed");

        Ok(EncryptedCombinedPath {
            indexes,
            ciphertext,
            leaf_node_index: self.leaf_index,
            with_leaf,
        })
    }
}

impl EncryptedCombinedPath {
    pub fn decrypt(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        decryption_key: &PkePrivateKey,
    ) -> Result<RegenerationSet, SumacError> {
        let length = self.indexes.len() + self.with_leaf as usize;
        let size = ciphersuite.hash_length();

        let raw_plaintext = decryption_key
            .decrypt_raw(provider.crypto(), ciphersuite, &self.ciphertext)
            .unwrap();
        assert_eq!(raw_plaintext.len(), size * length);

        let mut output = Vec::new();
        for chunk in raw_plaintext.chunks(size) {
            let secret = MlsSecret::from_slice(chunk);
            output.push(PathSecret::from(secret));
        }

        let (leaf_secret, path_secrets) = if self.with_leaf {
            let binding = output.remove(0);
            (Some(binding), output)
        } else {
            (None, output)
        };

        assert_eq!(path_secrets.len(), self.indexes.len());

        Ok(RegenerationSet {
            leaf_index: self.leaf_node_index,
            leaf_secret: leaf_secret.map(|l| l.secret().into()),
            path_secrets: self.indexes.clone().into_iter().zip(path_secrets).collect(),
        })
    }
}

///// Interfaces with the TMKA groups

impl TmkaAdminGroup {
    //// For regeneration: in the master group we regenerate the whole path
    pub(crate) fn build_regeneration_path(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        leaf_node_index: &LeafNodeIndex,
        is_including_leaf: bool,
    ) -> RegenerationSet {
        let diff = self.tree.empty_diff();

        let (leaf_secret, path_secrets) = diff.generate_regeneration_path(
            provider,
            ciphersuite,
            leaf_node_index,
            None,
            is_including_leaf,
        );

        RegenerationSet {
            leaf_index: *leaf_node_index,
            leaf_secret: leaf_secret.map(|s| s.into()),
            path_secrets: path_secrets
                .into_iter()
                .map(|(index, secret)| (index, secret.into()))
                .collect::<Vec<_>>(),
        }
    }

    pub(crate) fn build_regeneration_tree(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> RegenerationTree {
        let ratchet_tree: RatchetTree<LeafNodeTMKA, ParentNodeTMKA> =
            self.tree.export_ratchet_tree();

        let mut regenerated_nodes = vec![];
        for node in ratchet_tree.iter() {
            let new_node = node.clone().map(|either| {
                either.map_either(
                    |leaf: LeafNodeTMKA| {
                        leaf.derive_whole_leaf_regeneration(provider.crypto(), ciphersuite)
                            .unwrap()
                    },
                    |parent| {
                        parent
                            .derive_whole_parent_regeneration(provider.crypto(), ciphersuite)
                            .unwrap()
                    },
                )
            });

            regenerated_nodes.push(new_node);
        }

        let new_tree = RatchetTree::<LeafNodeTMKA, ParentNodeTMKA>::new(regenerated_nodes);

        RegenerationTree { tree: new_tree }
    }

    pub(crate) fn absorb_regeneration_path(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        regeneration_set: &RegenerationSet,
        replace_leaf_in_place: bool,
    ) -> CombinedPath {
        let mut diff = self.tree.empty_diff();
        let (regenerated_leaf, regenerated_secrets, commit_secret) = diff
            .absorb_regeneration_path(
                provider,
                ciphersuite,
                &regeneration_set.leaf_index(),
                None,
                &regeneration_set
                    .leaf_secret()
                    .map(|secret| Into::<MlsSecret>::into(secret.clone())),
                &regeneration_set
                    .path_secrets
                    .iter()
                    .map(|(index, path_secret)| (*index, path_secret.clone().secret()))
                    .collect(),
                replace_leaf_in_place,
            )
            .expect("Absorbtion failed");
        self.tree.merge_diff(diff.into_staged_diff().unwrap());

        self.commit_secret = commit_secret.into();

        CombinedPath {
            leaf_index: regeneration_set.leaf_index,
            leaf_secret: regenerated_leaf
                .map(|content| Into::<Secret>::into(content.leaf_secret().clone())),
            path_secrets: regenerated_secrets,
        }
    }

    pub(crate) fn absorb_regeneration_tree(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        regeneration_tree: RegenerationTree,
    ) -> Result<Secret, SumacError> {
        let old_tree = self.tree.export_ratchet_tree();

        let mut output = vec![];

        for (old_node, regen_node) in old_tree.iter().zip(regeneration_tree.tree.iter()) {
            let new_node = match (old_node, regen_node) {
                (Some(old_node), Some(regen_node)) => match (old_node, regen_node) {
                    (Either::Left(old_leaf), Either::Left(regen_leaf)) => old_leaf
                        .absorb_regeneration_secret(
                            provider.crypto(),
                            ciphersuite,
                            regen_leaf.leaf_secret().clone(),
                        )
                        .map_err(|e| SumacError::CryptoError(e))
                        .map(|leaf_node| Some(NodeVariant::Left(leaf_node))),
                    (Either::Right(old_parent), Either::Right(regen_parent)) => old_parent
                        .absorb_regeneration_secret(
                            provider.crypto(),
                            ciphersuite,
                            regen_parent
                                .path_secret()
                                .clone()
                                .expect("there should be a secret, because this is the admin tree")
                                .secret(),
                        )
                        .map_err(|e| SumacError::CryptoError(e))
                        .map(|parent_node| Some(NodeVariant::Right(parent_node))),
                    _ => Err(SumacError::TrueSumacError(
                        "The regeneration tree does njot have the same layout as the original one"
                            .to_owned(),
                    )),
                },
                (None, None) => Ok(None),
                _ => Err(SumacError::TrueSumacError(
                    "The regeneration tree does njot have the same layout as the original one"
                        .to_owned(),
                )),
            }?;
            output.push(new_node);
        }

        let index_root_in_ratchet = (output.len() - 1) / 2;
        let root_node = output
            .get(index_root_in_ratchet)
            .expect("The root should be full")
            .clone()
            .expect("The root should really be full");
        let final_secret = match root_node {
            Either::Left(_) => panic!("This should be a parent node"),
            Either::Right(actual_node) => actual_node
                .path_secret()
                .clone()
                .expect("The nsecret should be set"),
        };
        let commit_secret = final_secret.derive_path_secret(provider.crypto(), ciphersuite)?;

        let new_tree = TreeTMKA::from_ratchet_tree(RatchetTree::new(output));
        self.tree = new_tree;

        Ok(commit_secret.secret().into())
    }
}

impl TmkaSlaveGroup {
    //// For standard users: the regeneration starts at the root of the smaller subtree containing the own leaf index and the provided index
    pub fn build_regeneration_path(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        leaf_node_index: &LeafNodeIndex,
        is_with_leaf: bool,
    ) -> RegenerationSet {
        // recompute a regeneration path, starting from the leaf of the new user
        // cloner l'arbre et TOUT redériver
        let diff = self.tree.empty_diff();

        let (leaf_secret, path_secrets) = diff.generate_regeneration_path(
            provider,
            ciphersuite,
            leaf_node_index,
            Some(&self.own_leaf_index),
            is_with_leaf,
        );

        RegenerationSet {
            leaf_index: *leaf_node_index,
            leaf_secret: leaf_secret.map(|s| s.into()),
            path_secrets: path_secrets
                .into_iter()
                .map(|(index, secret)| (index, secret.into()))
                .collect::<Vec<_>>(),
        }
    }

    pub fn absorb_regeneration_path(
        &mut self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        regeneration_set: &RegenerationSet,
    ) -> Secret {
        let mut diff = self.tree.empty_diff();

        let (_, _, commit_secret) = diff
            .absorb_regeneration_path(
                provider,
                ciphersuite,
                &regeneration_set.leaf_index(),
                Some(&self.own_leaf_index),
                &regeneration_set
                    .leaf_secret()
                    .map(|secret| Into::<MlsSecret>::into(secret.clone())),
                &regeneration_set
                    .path_secrets
                    .iter()
                    .map(|(index, path_secret)| (*index, path_secret.clone().secret()))
                    .collect(),
                false,
            )
            .unwrap();

        self.tree.merge_diff(diff.into_staged_diff().unwrap());

        commit_secret.into()
    }
}

///// Useful to send the new tree to the new admin in a add-admin
pub struct RegenerationTree {
    pub tree: RatchetTree<LeafNodeTMKA, ParentNodeTMKA>,
}

pub struct EncryptedRegenerationTree {
    credentials: Vec<Credential>,
    encrypted_bitstream: HpkeCiphertext,
    indicators: Vec<bool>,
}

impl RegenerationTree {
    pub fn encrypt_hpke(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        encryption_key: &PkePublicKey,
    ) -> EncryptedRegenerationTree {
        let mut credentials = vec![];

        // concatenate_all_the_secrets in a gigantic bit stream
        let mut byte_stream_vec: Vec<Vec<u8>> = Vec::new();
        let mut indicators = Vec::new();
        for node in self.tree.iter() {
            if let Some(either) = node {
                match either {
                    Either::Left(leaf) => {
                        credentials.push(leaf.credential().clone());
                        let binding = leaf.leaf_secret().clone();
                        byte_stream_vec.push(binding.as_slice().to_vec())
                    }
                    Either::Right(parent) => {
                        let binding = parent.path_secret();
                        if let Some(secret) = binding {
                            let binding_bis = secret.clone().secret();
                            byte_stream_vec.push(binding_bis.as_slice().to_vec())
                        }
                    }
                }
                indicators.push(true);
            } else {
                indicators.push(false);
            }
        }

        let encryptions = encryption_key
            .encrypt(provider.crypto(), ciphersuite, &byte_stream_vec.concat())
            .unwrap();

        EncryptedRegenerationTree {
            credentials,
            encrypted_bitstream: encryptions,
            indicators,
        }
    }

    pub fn decrypt_hpke(
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        decryption_key: &PkePrivateKey,
        encrypted_regeneration_tree: EncryptedRegenerationTree,
    ) -> Self {
        let EncryptedRegenerationTree {
            credentials,
            encrypted_bitstream,
            indicators,
        } = encrypted_regeneration_tree;
        let size_secret = ciphersuite.hash_length();

        let plaintext = decryption_key
            .decrypt_raw(provider.crypto(), ciphersuite, &encrypted_bitstream)
            .unwrap();

        assert!(plaintext.len() % size_secret == 0);

        let mut decrypted_vec = Vec::new();
        for (index, chunk) in plaintext.chunks(size_secret).enumerate() {
            if *indicators.get(index).unwrap() {
                let secret = PathSecret::from(MlsSecret::from_slice(chunk));
                let either = if index % 2 == 0 {
                    //leaf case
                    Either::Left(
                        LeafNodeTMKA::new(
                            provider.crypto(),
                            ciphersuite,
                            credentials
                                .get(index / 2)
                                .expect("took the wrong credential")
                                .clone(),
                            secret.secret(),
                        )
                        .unwrap(),
                    )
                } else {
                    Either::Right(
                        ParentNodeTMKA::new_from_path_secret(
                            provider.crypto(),
                            ciphersuite,
                            secret,
                            None,
                        )
                        .unwrap(),
                    )
                };
                decrypted_vec.push(Some(either));
            } else {
                decrypted_vec.push(None)
            }
        }

        Self {
            tree: RatchetTree::<LeafNodeTMKA, ParentNodeTMKA>::new(decrypted_vec),
        }
    }
}
