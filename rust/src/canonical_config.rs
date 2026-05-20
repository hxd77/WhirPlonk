use sha3::{Digest, Sha3_256, Sha3_512};

use crate::{parameters::ProtocolParameters, protocols::whir_zk, transcript::DomainSeparator};

const WHIR_ZK_CONFIG_V1: &[u8] = b"WHIR_ZK_CONFIG_V1";

fn push_u64(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

#[must_use]
pub fn whir_zk_config_bytes(
    vector_size: usize,
    num_polynomials: usize,
    params: &ProtocolParameters,
    policy: &whir_zk::BlindingSizePolicy,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WHIR_ZK_CONFIG_V1);
    push_u64(&mut out, vector_size);
    push_u64(&mut out, num_polynomials);
    out.push(params.unique_decoding as u8);
    push_u64(&mut out, params.starting_log_inv_rate);
    push_u64(&mut out, params.initial_folding_factor);
    push_u64(&mut out, params.folding_factor);
    push_u64(&mut out, params.security_level);
    push_u64(&mut out, params.pow_bits);
    push_u64(&mut out, params.batch_size);
    out.extend_from_slice(params.hash_id.as_slice());
    push_u64(&mut out, policy.q_delta_1);
    push_u64(&mut out, policy.q_delta_2);
    push_u64(&mut out, policy.t1);
    push_u64(&mut out, policy.t2);
    push_u64(&mut out, policy.sumcheck_round_degree);
    out
}

#[must_use]
pub fn domain_separator_from_config_bytes(
    config_bytes: &[u8],
    session: &str,
) -> DomainSeparator<'static, ()> {
    let protocol_id: [u8; 64] = Sha3_512::digest(config_bytes).into();

    let mut session_hash = Sha3_256::new();
    ciborium::into_writer(session, &mut session_hash).expect("session cbor serialization failed");
    let session_id: [u8; 32] = session_hash.finalize().into();

    DomainSeparator::from_ids(protocol_id, session_id)
}

#[must_use]
pub fn whir_zk_domain_separator(
    vector_size: usize,
    num_polynomials: usize,
    params: &ProtocolParameters,
    policy: &whir_zk::BlindingSizePolicy,
    session: &str,
) -> (Vec<u8>, DomainSeparator<'static, ()>) {
    let config_bytes = whir_zk_config_bytes(vector_size, num_polynomials, params, policy);
    let ds = domain_separator_from_config_bytes(&config_bytes, session);
    (config_bytes, ds)
}
