//! This is a basic custom account contract that implements the
//! `FastAggregateVerify` function in [BLS
//! Signatures](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-fastaggregateverify)
//!
//! ⚠️ WARNING: it is indended for demonstration purpose only. It is not
//! security-audited and not safe to use in production (e.g. there is no proof
//! of possesion for the public key described in section 3.3).
#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface}, contract, contracterror, contractimpl, contracttype, crypto::Hash, log, vec, Bytes, BytesN, Env, Vec
};

#[contract]
pub struct IncrementContract;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Owners,
    Counter,
    Dst
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccError {
    InvalidSignature = 1,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedSignature {
    pub owner_mask: Vec<bool>,
    pub signature: BytesN<192>
}


mod bls_sigs;
use bls_sigs::{aggregate_pk_bytes, verify_bls_signature, PublicKey, DST};

#[contractimpl]
impl IncrementContract {
    pub fn init(env: Env, owners: Vec<PublicKey>) {
        log!(&env, "Init with owners", owners.len());
        env.storage().persistent().set(&DataKey::Owners, &owners);
        env.storage()
            .instance()
            .set(&DataKey::Dst, &Bytes::from_slice(&env, DST.as_bytes()));
        // initialize the counter, i.e. the business logic this signer contract
        // guards
        env.storage().instance().set(&DataKey::Counter, &0_u32);
    }

    pub fn increment(env: Env) -> u32 {
        env.current_contract_address().require_auth();
        let mut count: u32 = env.storage().instance().get(&DataKey::Counter).unwrap_or(0);
        count += 1;
        env.storage().instance().set(&DataKey::Counter, &count);
        count
    }
}

#[contractimpl]
impl CustomAccountInterface for IncrementContract {
    type Signature = WrappedSignature;
    type Error = AccError;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        agg_sig: Self::Signature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), AccError> {
        log!(&env, "check_auth", agg_sig);
        
        //get owners from storage
        let owners: Vec<PublicKey> = env.storage().persistent().get(&DataKey::Owners).unwrap();

        //apply mask to owners to get signers
        let mut signers: Vec<PublicKey> = vec![&env];
        for i in 0..owners.len() {
            if agg_sig.owner_mask.get(i).unwrap() {
                signers.push_back(owners.get(i).unwrap());
            }
        }
        log!(&env, "Number of signers", signers.len());
        
        //aggregate the signers
        let agg_pk: BytesN<96> = aggregate_pk_bytes(&env, &signers);
        log!(&env, "agg_pk", agg_pk);


        // Use the standalone verification function
        verify_bls_signature(&env, &signature_payload.into(), &agg_pk, &agg_sig.signature)
    }
}

mod test;
