// mod keccak256_hasher;
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

pub fn single_leaf_into_merge_value<H: Hasher + Default>(key: H256, value: H256, height: u8) -> MergeValue {
    // try keep hash same with MergeWithZero
    println!("key: {:?}", hex::encode(key.as_slice()));
    if value.is_zero() { // || height == 0 {
        MergeValue::from_h256(value)
    } else {
        // hash(chain_id, token_id, user)
        let base_key = key.parent_path(0);
        let base_node = hash_base_node::<H>(0, &base_key, &value);
        let mut zero_bits = key;

        let res = MergeValue::MergeWithZero {
            base_node,
            zero_bits,
            zero_count: height,
        };

        println!("--------------------------------------");
        println!("{:}", MV(res.clone()));
        println!("--------------------------------------");
        res
    }
}

fn get_k_v() -> Vec<(H256, SmtValue<ProfitStateData>)> {
    let mut k_v: Vec<(H256, SmtValue<ProfitStateData>)> = Vec::new();
    let token_id = Address::from_str("0x0000000000000000000000000000000000000021").unwrap();
    let mut chain_id = 100u64;
    let user: Address = Address::from_str("0x0000000000000000000000000000000000000022").unwrap();
    for i in 0..1 {
        let profit_state_data = ProfitStateData {
            token: token_id,
            token_chain_id: i,
            balance: U256::from(100),
            debt: U256::from(0),
        };
        let path = chain_token_address_convert_to_h256(i, token_id, user);
        println!(
            "path raw  chain_id: {:?}, token_id: {:?}, user:{:?}",
            i, token_id, user
        );
        let value = SmtValue::new(profit_state_data).unwrap();
        k_v.push((path, value));
        // chain_id += 1;
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

    if n == 0 {
        current_v = single_leaf_into_merge_value::<Keccak256Hasher>(key, v.to_h256(), 0);
        if let MergeWithZero {base_node, zero_bits, zero_count,} = &mut current_v {
            *zero_count = 0;
        }
    }

    println!("currenct_v hahahahah: {:}", MV(current_v.clone()));

    // 循环结束 获得新的root
    let new_root = current_v.hash::<Keccak256Hasher>();
    println!("new_root: {:?}", hex::encode(new_root.as_slice()));
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
    let mut tree = update_db(get_k_v());
    let root = tree.try_get_root().unwrap();
    println!("原来的root: {:?}", root);
    // let mut tree = new_state();
    for i in get_k_v() {
        // tree.try_update_all(vec![(i.clone().0, i.clone().1.get_data().clone())])
        //     .unwrap();
        // let root = tree.try_get_root().unwrap();
        let proof = tree.try_get_merkle_proof_1(i.0).unwrap();
        // let proof = tree.merkle_proof(vec![i.0]).unwrap();
        println!("path: {:?}", i.clone().0);
        // println!("key hex: {:?}", hex::encode(i.clone().0.as_slice()));
        println!("value raw: {:?}", i.clone().1.get_data());
        let hash = i.clone().1.to_h256();
        println!("value hash: {:?}", hash);
        let n_v = tree.try_get(i.0).unwrap();
        // assert_eq!(i.clone().1, n_v.unwrap());
        println!("bitmap: {:?}", proof.0);
        // let mut r_bitmap: SMTBitMap = proof.0.clone().into();
        // r_bitmap.reverse();
        // println!("reverse bitmap: {:?}", r_bitmap);
        println!("siblings: {:?}", proof.1);
        println!("root: {:?}", root);
        println!("----------hex------------");
        let path_hex = hex::encode(i.clone().0.as_slice());
        println!("path hash hex: {:?}", path_hex);
        println!("value hash hex: {:?}", hex::encode(hash.as_slice()));
        println!("bitmap hex: {:?}", hex::encode(proof.0.as_slice()));
        // println!(
        //     "reverse bitmap hex: {:?}",
        //     hex::encode(r_bitmap.0.as_slice())
        // );
        let mut n = 0;
        for i in &proof.1 {
            println!("sibling {:?} hex: {:}", n, MV(i.clone()));
            n += 1;
        }
        println!("root hex: {:?}", hex::encode(root.as_slice()));
        let res = verify(i.0, i.1, proof.0, proof.1, root.clone());
        assert_eq!(res, true);
        // tree.try_clear().unwrap();
        println!("--------------------------------------------------------------------------------------------------------------------");
    }

    let merge_zero_test: Vec<MergeValue> = serde_json::from_str(r#"[{"MergeWithZero":{"base_node":"6e52ca0838fa384a33fab3312877a5dd3af78facebf198f372da4301b6e47ce6","zero_bits":"d24c2a1d931f6b4444508e36f871ffcffc79712a63d8bbe04bf5417c5b000000","zero_count":235}},{"MergeWithZero":{"base_node":"0eec86eab2036d6155e8c6caf131196de53def9020b6367f9a4430aa85c233fc","zero_bits":"109771f05661cbe26c966a7af53579484baa691b032e8e16b734e53886400000","zero_count":236}},{"Value":"137a24269a9e8cb4a6af729db7e152bb4c0489c557f8867675b71b6dc370f6e6"},{"MergeWithZero":{"base_node":"6e642bc4e46eb9c958e548a30e32f1c7bf697ca2f7e0441bf9d618c061d0d7b2","zero_bits":"0000000000000000000000000000000000000000000000000000000000040000","zero_count":1}},{"Value":"1d841b03fded33fd3c3ebf26e43600ac6fc9ab5e7bbc9ee0b25a4f380db4a25a"},{"Value":"fb4f171f944da0f84361ce2e63301b778105960b991aa3ce242254d8ce98e911"},{"Value":"2e0e846bcca791734daf6f40cc4bdc07fbbacf436b17b42012b92e82511b79e1"},{"Value":"97b558ba0d0c9812605ac3b10f4f5fa0936524f3aba9df294e9e055e97083c84"},{"Value":"58bb8636498a6f553705f612f115fd3143b61e20cbb06005fe7db1a0d82be383"},{"Value":"631c80b53a5969f4ec347b1bd867b127d8dbf606b084f7e1a9b4ee8483db115c"},{"Value":"41f34cb8f7cddf4253ee1633c387b646742b1d66b2621dd3167dc9e699354c0a"},{"Value":"0e3b9e8970440f4a53455a17dc1032cda2b63840bd2ffeaa74d7224f256540ac"},{"Value":"428d327d3bd703576b3101123d3f42f584d5b642001e97dba48fb98793911565"},{"Value":"1417b46f8e7435132c7e3039d8d10563002dce67cc4a9503106572992317bbf5"},{"Value":"b176fb5027e9231c5d61b14467a951e921dc7aca192a97bb5ca0ee79fe39851e"},{"Value":"dd5331d1238d85a7028f300fc1011fb3576e8ea54e05e48081337845b3afda00"},{"Value":"d60f9807fdd18fcdd962f2470e1e1189e85f219120de72037bcd87bedc326b76"},{"Value":"b3ae46581ff7e9934650f3c4b3fa5ee408a47a86472a154818124675dfb6577c"},{"Value":"bda503ae7d1e0a35da118e4733392cfa1af4cf58c7a4aafa75154374181746f0"},{"Value":"523c060aaf7d4ec5c50bb0c74591482b37d16c985c514c9e57023017e1efaee9"},{"Value":"72b40309b386d6ad03b200f53588dd218f0d5cd4a928e2b442b51e6186f1f9c4"}]"#).unwrap();
    println!("merge_zero_test: {:?}", merge_zero_test);

    let merge_zero_test: Vec<MergeValue> = vec![];
    let path: [u8; 32] = hex::decode("228472fd6f523162da24fa644e8da8bfdafc670bafce779059382fc84993cff7").unwrap().try_into().unwrap();
    println!("path: {:?}", path);
    let leave_bitmap: [u8; 32] = [0; 32];
    // let leave_bitmap: [u8; 32] = hex::decode("00000000000000000000000000000000000000000000000000000000001fffff").unwrap().try_into().unwrap();
    let smt_value = SmtValue::new(ProfitStateData{
        token: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
        token_chain_id: 1,
        balance: U256::from_dec_str("20000000000000000").unwrap(),
        debt: U256::from_dec_str("0").unwrap(),
    }).unwrap();
    println!("smt_value: {:?}", smt_value);
    let root: [u8; 32] = hex::decode("f8254d6a52aafb1459b1e05dd7f5e2b6d7fbcf7973fa540670ed6bd2411c7cb3").unwrap().try_into().unwrap();
    let res = verify(path.into(), smt_value, leave_bitmap.into(), merge_zero_test, root.into());
    assert_eq!(res, true);


    let merge_zero_test: Vec<MergeValue> = vec![];
    let path: [u8; 32] = hex::decode("9a05d89903c318fd4a9bf0ec37a2341918b5d0783eab9743d65d5ef98e43efc2").unwrap().try_into().unwrap();
    println!("path: {:?}", path);
    let leave_bitmap: [u8; 32] = [0; 32];
    // let leave_bitmap: [u8; 32] = hex::decode("00000000000000000000000000000000000000000000000000000000001fffff").unwrap().try_into().unwrap();
    let smt_value = SmtValue::new(ProfitStateData{
        token: Address::from_str("0x29b6a77911c1ce3b3849f28721c65dada015c768").unwrap(),
        token_chain_id: 5,
        balance: U256::from_dec_str("169000000").unwrap(),
        debt: U256::from_dec_str("0").unwrap(),
    }).unwrap();
    println!("smt_value: {:?}", smt_value);
    let root: [u8; 32] = hex::decode("a0a75b9687bf81284b0c7bf901f914e1b23356870475ed48e052c771c4bfbff5").unwrap().try_into().unwrap();
    let res = verify(path.into(), smt_value, leave_bitmap.into(), merge_zero_test, root.into());
    assert_eq!(res, true);


    Ok(())
}







































// use sparse_merkle_tree::{
//     blake2b::Blake2bHasher, default_store::DefaultStore,
//     error::Error, MerkleProof,
//     SparseMerkleTree, traits::Value, H256
// };
// use blake2b_rs::{Blake2b, Blake2bBuilder};
//
// // define SMT
// type SMT = SparseMerkleTree<Blake2bHasher, Word, DefaultStore<Word>>;
//
// // define SMT value
// #[derive(Debug)]
// #[derive(Default, Clone)]
// pub struct Word(String);
// impl Value for Word {
//    fn to_h256(&self) -> H256 {
//        if self.0.is_empty() {
//            return H256::zero();
//        }
//        let mut buf = [0u8; 32];
//        let mut hasher = new_blake2b();
//        hasher.update(self.0.as_bytes());
//        hasher.finalize(&mut buf);
//        buf.into()
//    }
//    fn zero() -> Self {
//        Default::default()
//    }
// }
//
// // helper function
// fn new_blake2b() -> Blake2b {
//     Blake2bBuilder::new(32).personal(b"SMT").build()
// }
//
// fn construct_smt() {
//     let mut tree = SMT::default();
//     for (i, word) in "The quick brown fox jumps over the lazy dog"
//         .split_whitespace()
//         .enumerate()
//     {
//         let key: H256 = {
//             let mut buf = [0u8; 32];
//             let mut hasher = new_blake2b();
//             hasher.update(&(i as u32).to_le_bytes());
//             hasher.finalize(&mut buf);
//             buf.into()
//         };
//         let value = Word(word.to_string());
//         // insert key value into tree
//         println!("k: {:?}, v: {:?}", key, value);
//         tree.update(key, value).expect("update");
//     }
//
//     let root = tree.root();
//     println!("SMT root is {:?} ", root);
//     let path = H256::from([92, 221, 2, 166, 240, 78, 254, 46, 72, 94, 193, 12, 68, 186, 245, 57, 89, 114, 164, 75, 55, 145, 253, 102, 117, 163, 20, 46, 81, 160, 81, 67]);
//     let proof = tree.merkle_proof(vec![path]).unwrap().take();
//     let ver = verify(path,
//                      Word("The".to_string()), proof.0[0], proof.1, *root
//     );
//     assert_eq!(ver, true)
//
// }
//
// fn main() {
//     construct_smt();
// }