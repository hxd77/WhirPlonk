use std::borrow::Cow;

use ark_ff::Field;
use whir as whir_crate;

use whir_crate::{
    algebra::{
        embedding::Identity,
        fields::Field64,
        linear_form::{Covector, LinearForm},
    },
    canonical_config,
    deterministic_rng::DeterministicRng,
    hash,
    parameters::ProtocolParameters,
    protocols::{whir as whir_protocol, whir_zk},
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
};

type F = Field64;

fn dump_bytes(label: &str, data: &[u8]) {
    print!("    {label} ");
    for byte in data {
        print!("{byte:02x}");
    }
    println!();
}

fn dump_field_vec(label: &str, values: &[F]) {
    print!("    {label}");
    for value in values {
        print!(" {value}");
    }
    println!();
}

fn disable_whir_pow(config: &mut whir_protocol::Config<Identity<F>>) {
    config.initial_sumcheck.round_pow.threshold = u64::MAX;
    config.initial_skip_pow.threshold = u64::MAX;
    for round in &mut config.round_configs {
        round.sumcheck.round_pow.threshold = u64::MAX;
        round.pow.threshold = u64::MAX;
    }
    config.final_sumcheck.round_pow.threshold = u64::MAX;
    config.final_pow.threshold = u64::MAX;
}

fn disable_zk_pow(config: &mut whir_zk::Config<F>) {
    disable_whir_pow(&mut config.blinded_commitment);
    disable_whir_pow(&mut config.blinding_commitment);
}

fn main() {
    let num_variables = 8usize;
    let vector_size = 1usize << num_variables;
    let num_polynomials = 1usize;

    let params = ProtocolParameters {
        unique_decoding: false,
        security_level: 16,
        pow_bits: 0,
        initial_folding_factor: 2,
        folding_factor: 2,
        starting_log_inv_rate: 1,
        batch_size: 1,
        hash_id: hash::SHA2,
    };
    let policy = whir_zk::BlindingSizePolicy {
        q_delta_1: 4,
        q_delta_2: 4,
        t1: 4,
        t2: 4,
        sumcheck_round_degree: 3,
    };
    let mut config = whir_zk::Config::<F>::new_with_blinding_size_policy(
        vector_size,
        &params,
        num_polynomials,
        policy,
    );
    disable_zk_pow(&mut config);

    let poly = (0..vector_size)
        .map(|i| F::from((i as u64).wrapping_mul(17).wrapping_add(3)))
        .collect::<Vec<_>>();
    let vectors = [&poly[..]];
    let weight_vec = vec![F::ONE; vector_size];
    let forms_for_verify: Vec<Box<dyn LinearForm<F>>> =
        vec![Box::new(Covector::new(weight_vec.clone()))];
    let verify_refs = forms_for_verify
        .iter()
        .map(|f| f.as_ref() as &dyn LinearForm<F>)
        .collect::<Vec<_>>();
    let forms_for_prove: Vec<Box<dyn LinearForm<F>>> = vec![Box::new(Covector::new(weight_vec))];
    let evaluations = vec![poly.iter().copied().sum::<F>()];

    let (canonical_config, canonical_ds) = canonical_config::whir_zk_domain_separator(
        vector_size,
        num_polynomials,
        &params,
        &policy,
        "whir_zk_0",
    );
    let real_ds = DomainSeparator::protocol(&config).session(&"whir_zk_0");
    let ds = canonical_ds.instance(&Empty);
    let mut prover_state = ProverState::new_std(&ds);
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut rng = DeterministicRng::new(seed, "WHIR_ZK:mask");
    let witness = config.commit_with_rng(&mut prover_state, &vectors, &mut rng);

    println!("# SECTION whir_zk");
    dump_bytes("canonical_config", &canonical_config);
    dump_bytes("rust_real_ds_protocol_id", real_ds.protocol_id());
    dump_bytes("ds_protocol_id", ds.protocol_id());
    dump_bytes("ds_session_id", ds.session_id());
    dump_field_vec("input_vector0", &poly);
    dump_field_vec("f_hat_vector0", &witness.f_hat_vectors[0]);
    dump_field_vec("blinding_m_poly0", &witness.blinding_polynomials[0].m_poly);
    dump_field_vec("blinding_vector0", &witness.blinding_vectors[0]);

    let _claim = config.prove(
        &mut prover_state,
        vec![Cow::Borrowed(&poly)],
        witness,
        forms_for_prove,
        Cow::Borrowed(&evaluations),
    );
    let proof = prover_state.proof();
    dump_bytes("proof_narg", &proof.narg_string);
    dump_bytes("proof_hints", &proof.hints);

    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = config
        .receive_commitments(&mut verifier_state, num_polynomials)
        .expect("receive commitments");
    let verify_ok = config
        .verify(&mut verifier_state, &verify_refs, &evaluations, &commitment)
        .is_ok();
    println!("    verify {}", verify_ok as i32);
    println!(
        "    check_eof {}",
        verifier_state.check_eof().is_ok() as i32
    );
}
