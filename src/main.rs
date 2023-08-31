mod keccak256_hasher;
mod test;

// use tiny_keccak::{Hasher, Keccak};
use keccak256_hasher::Keccak256Hasher;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONNECTION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use sparse_merkle_tree::merge::hash_base_node;
use sparse_merkle_tree::traits::Hasher;
use std::fmt::{Display, Formatter};
// use ethers::abi::ParamType::Address;
use ethers::types::U256;
 use ethers::types::Address;
 use std::str::FromStr;
pub use rocksdb::prelude::Open;
pub use rocksdb::{DBVector, OptimisticTransaction, OptimisticTransactionDB};
use ethers::utils::{hex, keccak256};
// use sparse_merkle_tree::merge::into_merge_value;
use sparse_merkle_tree::merge::MergeValue::MergeWithZero;
use sparse_merkle_tree::merge::{merge, MergeValue};
use sparse_merkle_tree::traits::StoreReadOps;
use sparse_merkle_tree::{
    default_store::DefaultStore, error::Error, traits::Value, BranchKey, BranchNode, MerkleProof,
    SparseMerkleTree, H256,
};
use off_chain_state::{SmtValue, State};
use primitives::{types::ProfitStateData, func::chain_token_address_convert_to_h256};
use primitives::traits::StataTrait;

// define SMT
type SMT = SparseMerkleTree<Keccak256Hasher, SmtValue<ProfitStateData>, DefaultStore<SmtValue<ProfitStateData>>>;


pub fn into_merge_value<H: Hasher + Default>(key: H256, value: H256, height: u8) -> MergeValue {
    // try keep hash same with MergeWithZero
    if value.is_zero() || height == 0 {
        MergeValue::from_h256(value)
    } else {
        let base_key = key.parent_path(0);
        let base_node = hash_base_node::<H>(0, &base_key, &value);
        let mut zero_bits = key;
        for i in height..=core::u8::MAX {
            if key.get_bit(i) {
                zero_bits.clear_bit(i);
            }
        }
        MergeValue::MergeWithZero {
            base_node,
            zero_bits,
            zero_count: height,
        }
    }
}


fn get_k_v() -> Vec<(H256, SmtValue<ProfitStateData>)> {

    let mut k_v:  Vec<(H256, SmtValue<ProfitStateData>)> = Vec::new();
    let token_id = Address::from_str("0x0000000000000000000000000000000000000021").unwrap();
    let mut chain_id = 100u64;
    let user: Address = Address::from_str("0x0000000000000000000000000000000000000022").unwrap();
    for i in 0..1 {
        let profit_state_data = ProfitStateData {
            token: token_id,
            token_chain_id: chain_id,
            balance: U256::from(100),
            debt: U256::from(80),
        };
        let path = chain_token_address_convert_to_h256(chain_id, token_id, user);
        println!("path raw  chain_id: {:?}, token_id: {:?}, user:{:?}", chain_id, token_id, user);
        let value = SmtValue::new(profit_state_data).unwrap();
        k_v.push((path, value));
        chain_id += 1;
    }
    k_v
}

fn new_state() -> State<'static, Keccak256Hasher, ProfitStateData> {
    let db = OptimisticTransactionDB::open_default("./db1").unwrap();
    let prefix = b"test";
    State::new(prefix, db)
}
fn update_db(k_v: Vec<(H256, SmtValue<ProfitStateData>)>) -> State<'static, Keccak256Hasher, ProfitStateData> {
    let mut tree = new_state();
    for (key, value) in k_v {
        tree.try_update_all(vec![(key, value.get_data().clone())]).unwrap();
    }
    tree
}

fn verify(key: H256, v: SmtValue<ProfitStateData>, leaves_bitmap: H256, siblings: Vec<MergeValue>, root: H256) -> bool {
    // 定义初始路径
    let mut current_path = key;
    let mut n = 0;
    // 初始化节点的MergeValue
    let mut current_v = MergeValue::zero();

    // 定义左右节点的MergeValue
    let mut left: MergeValue = MergeValue::zero();
    let mut right: MergeValue = MergeValue::zero();

    // 循环遍历0到255（包括255）
    for i in 0..=u8::MAX {
        // 根据当前节点的路径得到父节点的路径
        let parent_path = current_path.parent_path(i);

        // 如果有兄弟节点（两个节点都是非零)
        if leaves_bitmap.get_bit(i) {
            // 如果第一次遇到非零节点 计算当前节点的MergeValue
            if n == 0 {
                // key和value都是最开始传进来的值
                current_v = into_merge_value::<Keccak256Hasher>(key, v.to_h256(), i);
            }
            if current_path.is_right(i) {
                left = siblings[n].clone();
                right = current_v.clone();
            } else {
                left = current_v.clone();
                right = siblings[n].clone();
            }

            n += 1;
        } else {
            // 遇到非零节点之后才会执行
            if n > 0 {
                if current_path.is_right(i) {
                    left = MergeValue::zero();
                    right = current_v.clone();
                } else {
                    left = current_v.clone();
                    right = MergeValue::zero();
                }
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
        }
    }
}

// 给一个打印MV的例子

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let mut tree = update_db(get_k_v());
    let root = tree.try_get_root().unwrap();
    for i in get_k_v() {
        let proof = tree.try_get_merkle_proof_1(i.0).unwrap();
        // let proof = tree.merkle_proof(vec![i.0]).unwrap();
        println!("path hash: {:?}", i.clone().0);
        // println!("key hex: {:?}", hex::encode(i.clone().0.as_slice()));
        println!("value raw: {:?}", i.clone().1.get_data());
        let hash = i.clone().1.to_h256();
        println!("value hash: {:?}", hash);
        let n_v = tree.try_get(i.0).unwrap();
        // assert_eq!(i.clone().1, n_v.unwrap());
        println!("bitmap: {:?}", proof.0);
        println!("siblings: {:?}", proof.1);
        println!("root: {:?}", root);
        println!("----------hex------------");
        println!("path hash hex: {:?}", hex::encode(i.clone().0.as_slice()));
        println!("value hash hex: {:?}", hex::encode(hash.as_slice()));
        println!(
            "bitmap hex: {:?}",
            hex::encode(proof.0.as_slice())
        );
        let mut n = 0;
        for i in &proof.1 {
            println!("sibling {:?} hex: {:}", n, MV(i.clone()));
            n += 1;
        }
        println!("root hex: {:?}", hex::encode(root.as_slice()));
        assert!(verify(
            i.0,
            i.1,
            proof.0,
            proof.1,
            root.clone()
        ));
        println!("--------------------------------------------------------------------------------------------------------------------");

        use sparse_merkle_tree::traits::Hasher;
        let mut hasher = Keccak256Hasher::default();
        hasher.write_byte(8);
        let f = hasher.finish();
        // println!("f: {:?}", f);
        // println!("f hex: {:?}", hex::encode(f.as_slice()));

    }
    Ok(())
}
