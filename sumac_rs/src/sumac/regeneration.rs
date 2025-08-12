use crate::{
    crypto::{hpke, secret::Secret},
    errors::SumacError,
    tmka::{admin_group::TmkaAdminGroup, user_group::TmkaSlaveGroup, TreeTMKA},
    user::User,
};
use either::Either;
use openmls::prelude::{BasicCredential, Credential, CredentialWithKey, Secret as MlsSecret};
use openmls::{
    prelude::{
        Ciphersuite, HpkeCiphertext, LeafNodeIndex, OpenMlsCrypto, ParentNodeIndex, PathSecret,
    },
    storage::OpenMlsProvider,
    tree_sumac::{
        nodes::encryption_keys::{PkePrivateKey, PkePublicKey, SymmetricKey},
        LeafNodeTMKA, OptionLeafNodeTMKA, ParentNodeTMKA, RatchetTree, SumacTree,
    },
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
        ciphersuite: Ciphersuite,
        key: &SymmetricKey,
    ) -> EncryptedRegenerationSet {
        let encrypted_secrets = self
            .path_secrets
            .iter()
            .map(|(index, path_secret)| {
                (
                    *index,
                    key.encrypt(crypto, ciphersuite, path_secret.clone().secret().as_slice())
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let encrypted_leaf_secret = self.leaf_secret.as_ref().map(|leaf_secret| {
            key.encrypt(crypto, ciphersuite, leaf_secret.as_slice().clone())
                .unwrap()
        });

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
        ciphersuite: Ciphersuite,
        key: &SymmetricKey,
    ) -> RegenerationSet {
        let plain_secrets = self
            .encrypted_path_secrets
            .iter()
            .map(|(index, path_secret)| {
                (
                    *index,
                    PathSecret::from(MlsSecret::from_slice(
                        key.decrypt(crypto, ciphersuite, path_secret)
                            .unwrap()
                            .as_slice(),
                    )),
                )
            })
            .collect();

        let leaf_secret = self.leaf_secret.as_ref().map(|leaf_secret| {
            Secret::from_slice(
                key.decrypt(crypto, ciphersuite, leaf_secret)
                    .unwrap()
                    .as_slice(),
            )
        });

        RegenerationSet {
            leaf_index: self.leaf_index,
            leaf_secret,
            path_secrets: plain_secrets,
        }
    }
}

pub type CombinedPath = RegenerationSet;

pub struct EncryptedCombinedPath{
    pub indexes : Vec<ParentNodeIndex>,
    pub ciphertext : HpkeCiphertext
}

impl CombinedPath {
    pub fn encrypt_hpke(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        encryption_key: &PkePublicKey,
    ) -> Result<EncryptedCombinedPath, SumacError> {

        let mut byte_stream_vec = Vec::new();
        let mut indexes = Vec::new();
        let path_secrets = self.path_secrets.clone();
        for (index, secret) in path_secrets.into_iter(){
            let binding = secret.clone().secret();
            byte_stream_vec.push(binding.as_slice().to_vec());
            indexes.push(index);
        }

        let ciphertext = encryption_key.encrypt(provider.crypto(), ciphersuite, &byte_stream_vec.concat()).expect("Encryption failed");

        // Ok(self
        //     .secrets()
        //     .into_iter()
        //     .map(|(index, path_secret)| {
        //         (
        //             *index,
        //             encryption_key
        //                 .encrypt(
        //                     provider.crypto(),
        //                     ciphersuite,
        //                     path_secret.clone().secret().as_slice(),
        //                 )
        //                 .expect("Encryption failed"),
        //         )
        //     })
        //     .collect())
        Ok(EncryptedCombinedPath{
            indexes,
            ciphertext,
        })
    }
}



impl EncryptedCombinedPath{
    pub fn decrypt(
        &self,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        decryption_key: &PkePrivateKey,
    ) -> Result<(Vec<ParentNodeIndex>, Vec<PathSecret>), SumacError>{
        let length = self.indexes.len();
        let size = ciphersuite.hash_length();
        
        let raw_plaintext = decryption_key.decrypt_raw(provider.crypto(), ciphersuite, &self.ciphertext).unwrap();
        assert_eq!(raw_plaintext.len(), size * length);

        let mut output = Vec::new();
        for chunk in raw_plaintext.chunks(size){
            let secret = MlsSecret::from_slice(chunk);
            output.push(PathSecret::from(secret));
        }


        Ok((self.indexes.clone(), output))
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
                            .derive__whole_parent_regeneration(provider.crypto(), ciphersuite)
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

pub struct EncryptedRegenerationTree{
    credentials : Vec<Credential>,
    encrypted_bitstream : HpkeCiphertext,
    indicators : Vec<bool>
}

impl RegenerationTree {
    //TODO: for now we do not use the full power of hpke. See how to improve this
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
        for (i, node) in self.tree.iter().enumerate() {
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
            }
            else{
                indicators.push(false);
            }
        }

        let encryptions = encryption_key
            .encrypt(provider.crypto(), ciphersuite, &byte_stream_vec.concat())
            .unwrap();

        ///////////////////////////////////////////////////////

        // let encryptions = self.tree
        //     .iter()
        //     .map(|node| {
        //         node.clone().map(|either|{
        //          let binding = match either {
        //             Either::Left(leaf) => {
        //                 credentials.push(leaf.credential().clone());
        //                 encryption_key
        //                 .encrypt(
        //                     provider.crypto(),
        //                     ciphersuite,
        //                     leaf.leaf_secret().as_slice(),
        //                 )
        //                 .unwrap()},
        //             Either::Right(parent) => encryption_key
        //                 .encrypt(
        //                     provider.crypto(),
        //                     ciphersuite,
        //                     parent.path_secret().clone().unwrap().secret().as_slice(),
        //                 )
        //                 .unwrap(),
        //             };
        //             binding
        //         })

        //     })
        //     .collect();

        EncryptedRegenerationTree { credentials, encrypted_bitstream: encryptions, indicators }
    }

    pub fn decrypt_hpke(
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
        decryption_key: &PkePrivateKey,
        // ciphertexts: Vec<Option<HpkeCiphertext>>,
        encrypted_regeneration_tree : EncryptedRegenerationTree
    ) -> Self {
        let EncryptedRegenerationTree{
            credentials,
            encrypted_bitstream,
            indicators
        } = encrypted_regeneration_tree;
        let size_secret = ciphersuite.hash_length();

        let plaintext = decryption_key
            .decrypt_raw(provider.crypto(), ciphersuite, &encrypted_bitstream)
            .unwrap();

        assert!(plaintext.len() % size_secret == 0);

        let mut decrypted_vec = Vec::new();
        for (index, chunk) in plaintext.chunks(size_secret).enumerate() {
            if *indicators.get(index).unwrap(){
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

            } else {decrypted_vec.push(None)}
           

        }

        // assert_eq!(2 * credentials.len(), ciphertexts.len() + 1);

        // let decrypted_vec = ciphertexts
        //     .into_iter()
        //     .enumerate()
        //     .map(|(index, node)| {
        //         node.map(|ciphertext| {
        //             let secret = decryption_key
        //                 .decrypt(provider.crypto(), ciphersuite, &ciphertext)
        //                 .unwrap();
        //             if index % 2 == 0 {
        //                 //leaf case
        //                 Either::Left(
        //                     LeafNodeTMKA::new(
        //                         provider.crypto(),
        //                         ciphersuite,
        //                        credentials.get(index / 2).expect("took the wrong credential").clone(),
        //                         secret.secret(),
        //                     )
        //                     .unwrap(),
        //                 )
        //             } else {
        //                 Either::Right(
        //                     ParentNodeTMKA::new_from_path_secret(
        //                         provider.crypto(),
        //                         ciphersuite,
        //                         secret,
        //                         None,
        //                     )
        //                     .unwrap(),
        //                 )
        //             }
        //         })
        //     })
        //     .collect();

        Self {
            tree: RatchetTree::<LeafNodeTMKA, ParentNodeTMKA>::new(decrypted_vec),
        }
    }
}
