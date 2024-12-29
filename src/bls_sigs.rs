use soroban_sdk::{
    bytesn, contracttype, crypto::bls12_381::{Fr, G1Affine, G2Affine}, vec, Bytes, BytesN, Env, Vec
};
use crate::AccError;

pub type PublicKey = BytesN<96>;
pub type SecretKey = BytesN<32>;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

// `DST `is the domain separation tag, intended to keep hashing inputs of your
// contract separate. Refer to section 3.1 in the [Hashing to Elliptic
// Curves](https://datatracker.ietf.org/doc/html/rfc9380) on requirements of
// DST.
pub const DST: &str = "BLSSIG-V01-CS01-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

pub fn verify_bls_signature(
    env: &Env,
    signature_payload: &Bytes,
    public_key: &BytesN<96>,
    signature: &BytesN<192>
) -> Result<(), AccError> {
    let bls = env.crypto().bls12_381();

    let neg_g1 = G1Affine::from_bytes(bytesn!(env, 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca));
    let msg_g2 = bls.hash_to_g2(signature_payload, &Bytes::from_slice(env, DST.as_bytes()));

    let vp1 = vec![env, G1Affine::from_bytes(public_key.clone()), neg_g1];
    let vp2 = vec![env, msg_g2, G2Affine::from_bytes(signature.clone())];

    if !bls.pairing_check(vp1, vp2) {
        return Err(AccError::InvalidSignature);
    }
    Ok(())
}

pub fn aggregate_pk_bytes(env: &Env, pks: &Vec<PublicKey>) -> PublicKey {
    let bls = env.crypto().bls12_381();
    let mut agg_pk = G1Affine::from_bytes(pks.get(0).unwrap());
    for i in 1..pks.len() {
        let pk = G1Affine::from_bytes(pks.get(i).unwrap());
        agg_pk = bls.g1_add(&agg_pk, &pk);
    }
    agg_pk.to_bytes()
}

pub fn sign_and_aggregate(env: &Env, msg: &Bytes, secret_keys: &Vec<SecretKey>) -> BytesN<192> {
    let bls = env.crypto().bls12_381();

    // convert secret keys to frs
    let mut frs: Vec<Fr> = vec![&env];
    for sk in secret_keys {
        frs.push_back(Fr::from_bytes(sk));
    }
    
    // hash msg to g2
    let dst = Bytes::from_slice(env, DST.as_bytes());
    let msg_g2 = bls.hash_to_g2(&msg, &dst);

    // create vec of msg_g2
    let mut vec_msg: Vec<G2Affine> = vec![&env];
    for _i in 0..frs.len() {
        vec_msg.push_back(msg_g2.clone())
    }

    // aggregate signatures
    bls.g2_msm(vec_msg, frs).to_bytes()
}