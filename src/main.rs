mod keccak256_hasher;

use keccak256_hasher::Keccak256Hasher;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONNECTION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use sparse_merkle_tree::merge::hash_base_node;
use sparse_merkle_tree::traits::Hasher;
use std::fmt::{Display, Formatter};

use ethers::utils::{hex, keccak256};
use sparse_merkle_tree::merge::into_merge_value;
use sparse_merkle_tree::merge::MergeValue::MergeWithZero;
use sparse_merkle_tree::merge::{merge, MergeValue};
use sparse_merkle_tree::traits::StoreReadOps;
use sparse_merkle_tree::{
    default_store::DefaultStore, error::Error, traits::Value, BranchKey, BranchNode, MerkleProof,
    SparseMerkleTree, H256,
};

// define SMT
type SMT = SparseMerkleTree<Keccak256Hasher, Word, DefaultStore<Word>>;

// define SMT value
#[derive(Default, Clone, Debug)]
pub struct Word(String);
impl Value for Word {
    fn to_h256(&self) -> H256 {
        if self.0.is_empty() {
            return H256::zero();
        }
        keccak256(self.0.as_bytes()).into()
    }
    fn zero() -> Self {
        Default::default()
    }
}

fn get_k_v() -> Vec<(H256, Word)> {
    let mut k_v = Vec::new();
    for (i, word) in "The word".split_whitespace().enumerate() {
        let key: H256 = keccak256(i.to_le_bytes()).into();
        let value = Word(word.to_string());
        k_v.push((key, value));
    }
    k_v
}

fn update_db(k_v: Vec<(H256, Word)>) -> SMT {
    let mut tree = SMT::default();
    for (key, value) in k_v {
        tree.update(key, value).expect("update");
    }
    tree
}

fn verify(key: H256, v: Word, leaves_bitmap: H256, siblings: Vec<MergeValue>, root: H256) -> bool {
    // 定义初始路径
    let mut current_path = key;
    let mut n = 0;
    // 初始化节点的MergeValue
    let mut current_v = MergeValue::ShortCut {
        key: key,
        value: keccak256(v.0.as_bytes()).into(),
        height: 0,
    };

    // 定义左右节点的MergeValue
    let mut left: MergeValue = MergeValue::zero();
    let mut right: MergeValue = MergeValue::zero();

    // 循环遍历0到255（包括255）
    for i in 0..=u8::MAX {
        // 根据当前节点的路径得到父节点的路径
        let parent_path = current_path.parent_path(i);

        // 如果有兄弟节点（两个节点都是非零)
        if leaves_bitmap.get_bit(i) {
            if current_path.is_right(i) {
                left = siblings[n].clone();
                right = current_v.clone();
            } else {
                left = current_v.clone();
                right = siblings[n].clone();
            }

            n += 1;
        }
        // 如果没有兄弟节点（遇到零的兄弟节点）
        else {
            if current_path.is_right(i) {
                left = MergeValue::zero();
                right = current_v.clone();
            } else {
                left = current_v.clone();
                right = MergeValue::zero();
            }
        }

        // 计算父节点的MergeValue  （高度， 父节点路径， 左节点， 右节点）
        current_v = merge::<Keccak256Hasher>(i, &parent_path, &left, &right);

        // 把父节点设置为当前节点
        current_path = parent_path;
    }

    // 循环结束 获得新的root
    let new_root = current_v.hash::<Keccak256Hasher>();
    new_root == root
}

#[derive(Debug)]
pub struct MV(MergeValue);

// 让[u8; 32]以hex的方式打印
impl Display for MV {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            MergeValue::Value(v) => write!(f, "{}", hex::encode(v.as_slice())),
            MergeValue::MergeWithZero {
                base_node,
                zero_bits,
                zero_count,
            } => write!(
                f,
                "base_node: {}, zero_bits: {}, zero_count: {}",
                hex::encode(base_node.as_slice()),
                hex::encode(zero_bits.as_slice()),
                zero_count
            ),
            MergeValue::ShortCut { key, value, height } => write!(
                f,
                "key: {}, value: {}, height: {}",
                hex::encode(key.as_slice()),
                hex::encode(value.as_slice()),
                height
            ),
        }
    }
}

// 给一个打印MV的例子

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let mut tree = update_db(get_k_v());
    let root = tree.root();
    for i in get_k_v() {
        let proof = tree.merkle_proof(vec![i.0]).unwrap();
        println!("key: {:?}", i.clone().0);
        // println!("key hex: {:?}", hex::encode(i.clone().0.as_slice()));
        println!("value: {:?}", i.clone().1);
        println!("bitmap: {:?}", proof.leaves_bitmap()[0]);
        println!("siblings: {:?}", proof.merkle_path().clone());
        println!("root: {:?}", root);
        println!("----------hex------------");
        println!("key hex: {:?}", hex::encode(i.clone().0.as_slice()));
        println!(
            "bitmap hex: {:?}",
            hex::encode(proof.leaves_bitmap()[0].as_slice())
        );
        let mut n = 0;
        for i in proof.merkle_path().clone() {
            println!("sibling {:?} hex: {:}", n, MV(i));
            n += 1;
        }
        println!("root hex: {:?}", hex::encode(root.as_slice()));
        assert!(verify(
            i.0,
            i.1,
            proof.leaves_bitmap()[0],
            proof.merkle_path().clone(),
            root.clone()
        ));
        println!("--------------------------------------------------------------------------------------------------------------------");
    }
    Ok(())
}
