mod keccak256_hasher;
mod test;

// use tiny_keccak::{Hasher, Keccak};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONNECTION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use sparse_merkle_tree::merge::hash_base_node;
use sparse_merkle_tree::traits::Hasher;
use std::fmt::{Display, Formatter};
// use ethers::abi::ParamType::Address;
use ethers::types::Address;
use ethers::types::U256;
use ethers::utils::{hex, keccak256};
pub use rocksdb::prelude::Open;
pub use rocksdb::{DBVector, OptimisticTransaction, OptimisticTransactionDB};
use std::str::FromStr;
// use sparse_merkle_tree::merge::into_merge_value;
use off_chain_state::{SmtValue, State, Keccak256Hasher};
use primitives::traits::StataTrait;
use primitives::{func::chain_token_address_convert_to_h256, types::ProfitStateData};
use sparse_merkle_tree::merge::MergeValue::MergeWithZero;
use sparse_merkle_tree::merge::{merge, MergeValue};
use sparse_merkle_tree::traits::StoreReadOps;
use sparse_merkle_tree::{
    default_store::DefaultStore, error::Error, traits::Value, BranchKey, BranchNode, MerkleProof,
    SparseMerkleTree, H256,
};
use utils::SMTBitMap;

// define SMT
type SMT = SparseMerkleTree<
    Keccak256Hasher,
    SmtValue<ProfitStateData>,
    DefaultStore<SmtValue<ProfitStateData>>,
>;

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
    let mut k_v: Vec<(H256, SmtValue<ProfitStateData>)> = Vec::new();
    let token_id = Address::from_str("0x0000000000000000000000000000000000000021").unwrap();
    let mut chain_id = 100u64;
    let user: Address = Address::from_str("0x0000000000000000000000000000000000000022").unwrap();
    for i in 0..2 {
        let profit_state_data = ProfitStateData {
            token: token_id,
            token_chain_id: chain_id,
            balance: U256::from(100),
            debt: U256::from(80),
        };
        let path = chain_token_address_convert_to_h256(chain_id, token_id, user);
        println!(
            "path raw  chain_id: {:?}, token_id: {:?}, user:{:?}",
            chain_id, token_id, user
        );
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
fn update_db(
    k_v: Vec<(H256, SmtValue<ProfitStateData>)>,
) -> State<'static, Keccak256Hasher, ProfitStateData> {
    let mut tree = new_state();
    for (key, value) in k_v {
        tree.try_update_all(vec![(key, value.get_data().clone())])
            .unwrap();
    }
    tree
}

fn verify(
    key: H256,
    v: SmtValue<ProfitStateData>,
    leaves_bitmap: H256,
    siblings: Vec<MergeValue>,
    root: H256,
) -> bool {
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
        // if i == 0 {
        //     current_v = into_merge_value::<Keccak256Hasher>(key, v.to_h256(), i);
        // }
        // 根据当前节点的路径得到父节点的路径
        let parent_path = current_path.parent_path(i);

        // 如果有兄弟节点（两个节点都是非零)
        if leaves_bitmap.get_bit(i) {
            println!("leaves_bitmap hahahah: {:?}", i);
            // 如果第一次遇到非零节点 计算当前节点的MergeValue
            if n == 0 {
                // key和value都是最开始传进来的值
                current_v = into_merge_value::<Keccak256Hasher>(key, v.to_h256(), i);
                match current_v {
                    MergeValue::MergeWithZero { base_node, zero_bits, zero_count } => {
                        println!("current_v: {:?}", current_v);
                        println!("base_node: {:?}", base_node);
                        println!("zero_bits: {:?}", hex::encode(zero_bits.as_slice()));
                        println!("zero_count: {:?}", zero_count);
                        println!("----------------------------------");
                    },
                    _ => {
                        println!("haha");
                    }
                }


            }
            // 在这个高度上如果是0 那么就说明在右边
            if current_path.is_right(i) {
                println!("current path hahahah: {:?}, {:?}", i, current_path);
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
    println!("new_root: {:?}", new_root);
    new_root == root
}

#[derive(Debug)]
pub struct MV(MergeValue);

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
    // let mut tree = update_db(get_k_v());
    // let root = tree.try_get_root().unwrap();
    // println!("原来的root: {:?}", root);
    // for i in get_k_v() {
    //     let proof = tree.try_get_merkle_proof_1(i.0).unwrap();
    //     // let proof = tree.merkle_proof(vec![i.0]).unwrap();
    //     println!("path: {:?}", i.clone().0);
    //     // println!("key hex: {:?}", hex::encode(i.clone().0.as_slice()));
    //     println!("value raw: {:?}", i.clone().1.get_data());
    //     let hash = i.clone().1.to_h256();
    //     println!("value hash: {:?}", hash);
    //     let n_v = tree.try_get(i.0).unwrap();
    //     // assert_eq!(i.clone().1, n_v.unwrap());
    //     println!("bitmap: {:?}", proof.0);
    //     // let mut r_bitmap: SMTBitMap = proof.0.clone().into();
    //     // r_bitmap.reverse();
    //     // println!("reverse bitmap: {:?}", r_bitmap);
    //     println!("siblings: {:?}", proof.1);
    //     println!("root: {:?}", root);
    //     println!("----------hex------------");
    //     let path_hex = hex::encode(i.clone().0.as_slice());
    //     println!("path hash hex: {:?}", path_hex);
    //     println!("value hash hex: {:?}", hex::encode(hash.as_slice()));
    //     println!("bitmap hex: {:?}", hex::encode(proof.0.as_slice()));
    //     // println!(
    //     //     "reverse bitmap hex: {:?}",
    //     //     hex::encode(r_bitmap.0.as_slice())
    //     // );
    //     let mut n = 0;
    //     for i in &proof.1 {
    //         println!("sibling {:?} hex: {:}", n, MV(i.clone()));
    //         n += 1;
    //     }
    //     println!("root hex: {:?}", hex::encode(root.as_slice()));
    //     let res = verify(i.0, i.1, proof.0, proof.1, root.clone());
    //     assert_eq!(res, true);
    //     println!("--------------------------------------------------------------------------------------------------------------------");
    // }

    let merge_zero_test: Vec<MergeValue> = serde_json::from_str(r#"[
        {
          "MergeWithZero": {
            "base_node": "cb94570ff66a24b3b9ac5def9e60f57ba8818ab1490a04b8691b5b87754fef59",
            "zero_bits": "a601f68f6e500fbd43af909a8dd5b339ae93ee3f850d460294638cd62c800000",
            "zero_count": 235
          }
        },
        {
          "MergeWithZero": {
            "base_node": "72fc42e581245915da79a7105abb19f9db9abbfebf00df4bcb55798a3004b2c0",
            "zero_bits": "dace0803823fb988e3248764ef7e58bd2f2ca3e474b7d4e72c51f20e84200000",
            "zero_count": 236
          }
        },
        {
          "Value": "736aab38c341a3d6f804dc87097b42ec07cf6c2c64869d98eedec488812d27fc"
        },
        {
          "Value": "0fe52ffe3145c718f7b98af0d0b5ce8f34ae70de742c5ca528bb66039b83b4ef"
        },
        {
          "Value": "8657937b2f2f9e75ab48d94d8e05eb486007c1a8c6064579f1dbe0533ab31a26"
        },
        {
          "Value": "df08938a7ff0a171b9d32b17521be6bd7613c3ed5f17c19a29fa9abda5a694d1"
        },
        {
          "Value": "a75803cd59428696a6bd7b1a2788128131027de236d0114b73f146c5e80d32ff"
        },
        {
          "Value": "07b35a43dfad4b5d4a9b4b8a368ec6ef5e4852a853f0c3f313c62e83fa70130e"
        },
        {
          "Value": "6bd84f19376ca507418bc41c9dfe93e8735ed0774849166ac81e0fade5d7080e"
        },
        {
          "Value": "02166982883d9fbbe62fac15e889162693d9f60606f5b69792271a474307fbb3"
        },
        {
          "Value": "09852282d499d79f98d66b1cad59d8ecdbd7ef79c94cf6cc457c63ae3f75fe95"
        },
        {
          "Value": "52c00bc047f59927e7d369495ec8217d61413b9cb8e100a771b345e4a44c1c10"
        },
        {
          "Value": "8a0845f712528d0e413813ec65bbc256a02fded4f9cab9743b15d6748ee23fc5"
        },
        {
          "Value": "0c456db91bc00110175b9e78d1b6a3e2599dd30d67c3d615377b29a4c46672e2"
        },
        {
          "Value": "2544a28341b5347b8833394aa772ba6cb670130071f337bc7e9b96d1caddf56e"
        },
        {
          "Value": "3d3720ce4187642f86fa67b34ce351186678682c5b56e47fac1f1f93d38aa3ab"
        },
        {
          "Value": "78b02cb7bd4ab75dcfd3904ca1547543c29a8d6369cec09bc9450d1646c54547"
        },
        {
          "Value": "5f135f50432de53baf4dfa04ebc3ccd289ecb3d26a5842649c9e761bd0cc6572"
        },
        {
          "Value": "3ddde1c194ba605a31354699ef78eeca4d067a8c278805c7b7546440e4ca2122"
        },
        {
          "Value": "184d65a6237327dcbf1ea6aa755f80b2c3c577f142e2c4f19c103840e6847de9"
        }
      ]"#).unwrap();
    println!("merge_zero_test: {:?}", merge_zero_test);

    let path: [u8; 32] = hex::decode("80a03e756483799ea1217bdc67fd7dc8e514537e8e0bfd8fab730a67fc7edf34").unwrap().try_into().unwrap();
    let leave_bitmap: [u8; 32] = hex::decode("00000000000000000000000000000000000000000000000000000000001bffff").unwrap().try_into().unwrap();
    let smt_value = SmtValue::new(ProfitStateData{
        token: Address::from_str("0xa0321efeb50c46c17a7d72a52024eea7221b215a").unwrap(),
        token_chain_id: 5,
        balance: U256::from_dec_str("112000000000000000000").unwrap(),
        debt: Default::default(),
    }).unwrap();
    let root: [u8; 32] = hex::decode("223395a9aefe2672468363c3fc05113edfdce890bd3ad7fd465bfd0a2544be31").unwrap().try_into().unwrap();
    let res = verify(path.into(), smt_value, leave_bitmap.into(), merge_zero_test, root.into());
    assert_eq!(res, true);
    Ok(())
}
