#![cfg(test)]

use super::*;
#[test]
fn test() {

    // let v: Vec<u8> = vec![1, 2, 3];
    // let e = hex::encode(v.as_slice());
    // println!("v encode: {:?}", e);
    // let a = hex::decode("0x010203").unwrap();
    // println!("a: {:?}", a);
    let MERGE_ZEROS: u8 = 2;
    let base_node = hex::decode("0xda5ba67fe3c320cad65e31750c911f7e013bfbb6148162df1f7deb571b73ecb2").unwrap();
    let zero_bits = hex::decode("0x4a2098bdad450c29aaaebb661ecbe76347ba424058e2be3383a344c9f664eb00").unwrap();
    let zero_count: u8 = 248;
    let bn: [u8; 32] = base_node.as_slice().try_into().unwrap();
    println!("bn: {:?}", bn);
    println!("bn hex:{:?}", hex::encode(bn));
    let zb: [u8; 32] = zero_bits.as_slice().try_into().unwrap();
    let mut hasher = Keccak256Hasher::default();
    // hasher.write_byte(MERGE_ZEROS);
    hasher.write_h256(&H256::from(bn));
    hasher.write_h256(&H256::from(zb));
    // hasher.write_byte(zero_count);
    let res = hasher.finish();
    println!("res hex: {:?}", hex::encode(res.as_slice()));



}