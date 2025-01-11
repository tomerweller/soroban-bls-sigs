#![cfg(test)]
extern crate std;

use soroban_sdk::{
    testutils::BytesN as _, vec, BytesN, Env, IntoVal, Vec
};

use crate::{bls_sigs::{sign_and_aggregate, KeyPair, PublicKey, SecretKey}, AccError, IncrementContract, IncrementContractClient, WrappedSignature};
use blst::min_pk::SecretKey as BLST_SecretKey;


/// create a keypair from a random 32 byte array
/// this function is here and not in bls_sigs.rs because it uses BLST which can not be compiled to wasm
pub fn create_keypair(e: &Env, ikm: [u8; 32]) -> KeyPair {
    let sk = BLST_SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    KeyPair {
        sk: BytesN::from_array(&e, &sk.to_bytes()),
        pk: BytesN::from_array(&e, &pk.serialize()),
    }
}
/// test that the contract authorizes a signature that was aggregated from a subset of the public keys
#[test]
fn test_correct_aggregation() {
    let e: Env = Env::default();
    let client = IncrementContractClient::new(&e, &e.register(IncrementContract {}, ()));

    //create 3 keypairs
    let kp1 = create_keypair(&e, rand::random());
    let kp2 = create_keypair(&e, rand::random());
    let kp3 = create_keypair(&e, rand::random());
    let pks = vec![&e, kp1.pk, kp2.pk, kp3.pk];
    client.init(&pks);

    let payload = BytesN::random(&e);
    let wrapped_sig = WrappedSignature {
        owner_mask: vec![&e, true, false, true],
        signature: sign_and_aggregate(&e, &payload.clone().into(), &vec![&e, kp1.sk, kp3.sk]),
    };

    e.try_invoke_contract_check_auth::<AccError>(
        &client.address, 
        &payload, 
        wrapped_sig.into_val(&e), 
        &vec![&e]).unwrap();
}

/// test that the contract does not authorize a signature that does not match the aggregated subset of public keys
#[test]
fn test_incorrect_aggregation() {
    let e: Env = Env::default();
    let client = IncrementContractClient::new(&e, &e.register(IncrementContract {}, ()));

    let kp1 = create_keypair(&e, rand::random());
    let kp2 = create_keypair(&e, rand::random());
    let kp3 = create_keypair(&e, rand::random());
    let pks = vec![&e, kp1.pk, kp2.pk, kp3.pk];
    client.init(&pks);

    let payload = BytesN::random(&e);
    let wrapped_sig = WrappedSignature {
        owner_mask: vec![&e, true, true, false],
        signature: sign_and_aggregate(&e, &payload.clone().into(), &vec![&e, kp1.sk, kp3.sk]),
    };

    let _err = e.try_invoke_contract_check_auth::<AccError>(
        &client.address, 
        &payload, 
        wrapped_sig.into_val(&e), 
        &vec![&e]).unwrap_err();
}

fn test_with_keys(e: &Env, client: &IncrementContractClient, public_keys: &Vec<PublicKey>, secret_keys: &Vec<SecretKey>) { 
    
    // reset the budget to unlimited to avoid the budget limit for initialization
    e.cost_estimate().budget().reset_unlimited();
    if let Err(err) = client.try_init(&public_keys) {
        std::println!("Init Inovcation failed with error: {:?}", err);
    }
    
    let payload = BytesN::random(&e);
    let sig_val: BytesN<192>= sign_and_aggregate(&e, &payload.clone().into(), secret_keys);
    
    //create a mask with true for all keys
    let mut owner_mask: Vec<bool> = vec![&e];
    for _i in 0..public_keys.len() {
        owner_mask.push_back(true);
    }

    let wrapped_sig = WrappedSignature {
        owner_mask: owner_mask.clone(),
        signature: sig_val.clone(),
    };

    e.cost_estimate().budget().reset_default();
    if let Err(err) = e.try_invoke_contract_check_auth::<AccError>(
        &client.address, 
        &payload, 
        wrapped_sig.into_val(e), 
        &vec![&e]) {
        std::println!("Auth invocation failed with error: {:?}", err);
        // std::println!("Instructions: {:#?}", e.cost_estimate().resources().instructions);
        // std::println!("{:#?}", e.cost_estimate().budget());
    }
    std::println!("Instructions: {:#?}", e.cost_estimate().resources().instructions);

}

mod wasm_contract {
    //todo: why is this needed?
    use crate::bls_sigs::{PublicKey, SecretKey};
    use soroban_sdk::auth::Context;
    
    soroban_sdk::contractimport!(
        file = "target/wasm32-unknown-unknown/release/soroban_bls_signature.wasm"
    );
}

#[test]
fn test() {
    let key_count = 1000;
    let local = false;
    let e: Env = Env::default();
    e.mock_all_auths();

    // create n keypairs and respective vectors of public keys and secret keys
    let mut public_keys: Vec<PublicKey> = vec![&e];
    let mut secret_keys: Vec<SecretKey> = vec![&e];
    for _i in 0..key_count {
        let kp = create_keypair(&e, rand::random());
        public_keys.push_back(kp.pk);
        secret_keys.push_back(kp.sk);
    }

    for i in 540..560 {
        std::println!("testing with {:#?} keys", i);
        let pks = public_keys.slice(0..i as u32);
        let sks = secret_keys.slice(0..i as u32);
        let client = if local {
            IncrementContractClient::new(&e, &e.register(IncrementContract {}, ()))
        } else {
            IncrementContractClient::new(&e, &e.register(wasm_contract::WASM, ()))
        };
        test_with_keys(&e, &client, &pks, &sks);  
    }
}
