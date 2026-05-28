use std::{borrow::Cow, time::Instant};

#[cfg(feature = "rs_in_order")]
use ark_ff::Field;
use ark_std::rand::distributions::{Distribution, Standard};
use clap::Parser;
use sha3::{Digest, Sha3_256, Sha3_512};
use whir::{
    algebra::{
        embedding::{Basefield, Embedding, Identity},
        fields::{Field128, Field192, Field256, Field64, Field64_2, Field64_3},
        linear_form::{Covector, Evaluate, LinearForm, MultilinearExtension},
    },
    bits::Bits,
    cmdline_utils::{AvailableFields, AvailableHash},
    hash::HASH_COUNTER,
    parameters::ProtocolParameters,
    transcript::{codecs::Empty, Codec, DomainSeparator, ProverState, VerifierState},
};

/// 构造与 C++ 端一致的 DomainSeparator（protocol_id = SHA3-512(CBOR:0xBEEF),
/// session_id = SHA3-256(CBOR:"WHIR_test")）。
fn make_unified_ds<'a>() -> DomainSeparator<'a, ()> {
    // protocol_id = SHA3-512([0x19, 0xBE, 0xEF])   — CBOR uint 0xBEEF
    let mut hasher = Sha3_512::new();
    hasher.update([0x19, 0xBE, 0xEF]);
    let protocol_id: [u8; 64] = hasher.finalize().into();
    // session_id = SHA3-256(CBOR("WHIR_test"))
    // CBOR: text header 0x69 (9 byte) + b"WHIR_test"
    let mut hasher = Sha3_256::new();
    hasher.update([0x69, 0x57, 0x48, 0x49, 0x52, 0x5F, 0x74, 0x65, 0x73, 0x74]);
    let session_id: [u8; 32] = hasher.finalize().into();
    DomainSeparator::with_ids(protocol_id, session_id, &())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'l', long, default_value = "128")]
    security_level: usize,

    /// Maximum proof of work difficulty in bits.
    #[arg(short = 'p', long, default_value = "20")]
    pow_bits: usize,

    #[arg(short = 'd', long, default_value = "20")]
    num_variables: usize,

    #[arg(short = 'e', long = "evaluations", default_value = "1")]
    num_evaluations: usize,

    #[arg(long = "linear-constraints", default_value = "0")]
    num_linear_constraints: usize,

    #[arg(short = 'r', long, default_value = "1")]
    rate: usize,

    #[arg(long = "reps", default_value = "1000")]
    verifier_repetitions: usize,

    #[arg(short = 'i', long = "initfold", default_value = "4")]
    first_round_folding_factor: usize,

    #[arg(short = 'k', long = "fold", default_value = "4")]
    folding_factor: usize,

    /// Restrict PCS to the Unique Decoding regime. LDT is always UD.
    #[arg(long = "unique-decoding", default_value_t = false)]
    unique_decoding: bool,

    #[arg(short = 'f', long = "field", default_value = "Goldilocks3")]
    field: AvailableFields,

    #[arg(long = "hash", default_value = "Blake3")]
    hash: AvailableHash,

    #[arg(long = "zk")]
    zk: bool,

    /// ZK 模式的确定性随机种子（0 表示使用熵源）。
    #[arg(long = "seed", default_value = "0")]
    seed: u64,
}

fn main() {
    use AvailableFields as AF;
    let args = Args::parse();
    let field = args.field;

    // Dispatch on embedding
    if args.zk {
        #[cfg(not(feature = "rs_in_order"))]
        panic!("ZK requires --features rs_in_order");
        #[cfg(feature = "rs_in_order")]
        match field {
            AF::Goldilocks1 => run_whir_zk::<Field64>(&args),
            AF::Goldilocks2 => run_whir_zk::<Field64_2>(&args),
            AF::Goldilocks3 => run_whir_zk::<Field64_3>(&args),
            AF::Field128 => run_whir_zk::<Field128>(&args),
            AF::Field192 => run_whir_zk::<Field192>(&args),
            AF::Field256 => run_whir_zk::<Field256>(&args),
        }
    } else {
        match field {
            AF::Goldilocks1 => run_whir::<Identity<Field64>>(&args),
            AF::Goldilocks2 => run_whir::<Basefield<Field64_2>>(&args),
            AF::Goldilocks3 => run_whir::<Basefield<Field64_3>>(&args),
            AF::Field128 => run_whir::<Identity<Field128>>(&args),
            AF::Field192 => run_whir::<Identity<Field192>>(&args),
            AF::Field256 => run_whir::<Identity<Field256>>(&args),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_whir<M>(args: &Args)
where
    Standard: Distribution<M::Source> + Distribution<M::Target>,
    M: Embedding + Default,
    M::Target: Codec,
{
    use whir::protocols::whir::Config;

    // Runs as a PCS
    let security_level = args.security_level;
    let pow_bits = args.pow_bits;
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;
    let first_round_folding_factor = args.first_round_folding_factor;
    let folding_factor = args.folding_factor;
    let unique_decoding = args.unique_decoding;
    let num_evaluations = args.num_evaluations;
    let num_linear_constraints = args.num_linear_constraints;
    let hash_id = args.hash.hash_id();

    if num_evaluations + num_linear_constraints == 0 {
        println!("No constraints specified, running as low-degree-test.");
    }

    let num_coeffs = 1 << num_variables;

    let whir_params = ProtocolParameters {
        security_level,
        pow_bits,
        initial_folding_factor: first_round_folding_factor,
        folding_factor,
        unique_decoding,
        starting_log_inv_rate: starting_rate,
        batch_size: 1,
        hash_id,
    };

    let params = Config::<M>::new(1 << num_variables, &whir_params);

    let ds = make_unified_ds().instance(&Empty);

    let mut prover_state = ProverState::new_std(&ds);

    println!("=========================================");
    println!("Whir (PCS) 🌪️");
    println!("Field: {:?} and hash: {:?}", args.field, args.hash);
    println!("{params}");
    if !params.check_max_pow_bits(Bits::new(whir_params.pow_bits as f64)) {
        println!("WARN: more PoW bits required than specified.");
    }

    let vector = (0..num_coeffs)
        .map(|i| M::Source::from(i as u64))
        .collect::<Vec<_>>();

    let (witness, whir_commit_time) = {
        let _phase = whir::profiling::PhaseGuard::new("commit");
        let start = Instant::now();
        let witness = params.commit(&mut prover_state, &[&vector]);
        let elapsed = start.elapsed();
        whir::profiling::record("prover", num_coeffs, "commit_total", elapsed);
        (witness, elapsed)
    };

    // Allocate constraints
    let mut linear_forms: Vec<Box<dyn Evaluate<M>>> = Vec::new();
    let mut prove_linear_forms: Vec<Box<dyn LinearForm<M::Target>>> = Vec::new();
    let mut evaluations = Vec::new();

    // Linear constraint
    // We do these first to benefit from buffer recycling.
    for _ in 0..num_linear_constraints {
        let linear_form = Box::new(Covector {
            vector: (0..num_coeffs).map(|i| M::Target::from(i as u64)).collect(),
        });
        evaluations.push(linear_form.evaluate(params.embedding(), &vector));
        linear_forms.push(linear_form.clone());
        prove_linear_forms.push(linear_form);
    }

    // Evaluation constraint
    let points: Vec<_> = (0..num_evaluations)
        .map(|x| vec![M::Target::from(x as u64); num_variables])
        .collect();
    for point in &points {
        let linear_form = Box::new(MultilinearExtension::new(point.clone()));
        evaluations.push(linear_form.evaluate(params.embedding(), &vector));
        linear_forms.push(linear_form.clone());
        prove_linear_forms.push(linear_form);
    }

    let whir_prove_time = {
        let _phase = whir::profiling::PhaseGuard::new("prove");
        let start = Instant::now();
        let _ = params.prove(
            &mut prover_state,
            vec![Cow::Borrowed(vector.as_slice())],
            vec![Cow::Owned(witness)],
            prove_linear_forms,
            Cow::Borrowed(evaluations.as_slice()),
        );
        let elapsed = start.elapsed();
        whir::profiling::record("prover", num_coeffs, "prove_total", elapsed);
        elapsed
    };
    whir::profiling::record(
        "prover",
        num_coeffs,
        "total_prover",
        whir_commit_time + whir_prove_time,
    );

    let proof = prover_state.proof();
    println!(
        "Prover time: {whir_commit_time:.1?} + {whir_prove_time:.1?} = {:.1?}",
        whir_commit_time + whir_prove_time,
    );
    println!(
        "Proof size: {:.1} KiB",
        (proof.narg_string.len() + proof.hints.len()) as f64 / 1024.0
    );

    HASH_COUNTER.reset();
    let whir_verifier_time = Instant::now();
    for _ in 0..reps {
        let mut verifier_state = VerifierState::new_std(&ds, &proof);

        let commitment = params.receive_commitment(&mut verifier_state).unwrap();
        let final_claim = params
            .verify(&mut verifier_state, &[&commitment], &evaluations)
            .unwrap();
        final_claim
            .verify(
                linear_forms
                    .iter()
                    .map(|w| w.as_ref() as &dyn LinearForm<M::Target>),
            )
            .unwrap();
    }
    println!(
        "Verifier time: {:.1?}",
        whir_verifier_time.elapsed() / reps as u32
    );
    println!(
        "Average hashes: {:.1}k",
        (HASH_COUNTER.get() as f64 / reps as f64) / 1000.0
    );
}

#[cfg(feature = "rs_in_order")]
#[allow(clippy::too_many_lines)]
fn run_whir_zk<F>(args: &Args)
where
    Standard: Distribution<F>,
    F: Field + Codec,
{
    use whir::protocols::whir_zk::Config;

    let security_level = args.security_level;
    let pow_bits = args.pow_bits;
    let num_variables = args.num_variables;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;
    let first_round_folding_factor = args.first_round_folding_factor;
    let folding_factor = args.folding_factor;
    let num_evaluations = args.num_evaluations;
    let num_linear_constraints = args.num_linear_constraints;
    let hash_id = args.hash.hash_id();

    if num_evaluations + num_linear_constraints == 0 {
        println!("No constraints specified, running as low-degree-test.");
    }

    let num_coeffs = 1 << num_variables;

    let whir_params = ProtocolParameters {
        unique_decoding: args.unique_decoding,
        security_level,
        pow_bits,
        initial_folding_factor: first_round_folding_factor,
        folding_factor,
        starting_log_inv_rate: starting_rate,
        batch_size: 1,
        hash_id,
    };

    let params = Config::<F>::new(1 << num_variables, &whir_params, 1);

    let ds = make_unified_ds().instance(&Empty);

    let mut prover_state = ProverState::new_std(&ds);

    println!("=========================================");
    println!("Whir (PCS + ZK) 🌪️");
    println!("Field: {:?} and hash: {:?}", args.field, args.hash);
    println!("{params}");
    if !params
        .blinded_commitment
        .check_max_pow_bits(Bits::new(whir_params.pow_bits as f64))
    {
        println!("WARN: more PoW bits required than specified.");
    }

    let embedding = Identity::<F>::new();
    let vector = (0..num_coeffs).map(F::from).collect::<Vec<_>>();

    // Allocate constraints
    let mut linear_forms: Vec<Box<dyn Evaluate<Basefield<F>>>> = Vec::new();
    let mut prove_linear_forms: Vec<Box<dyn LinearForm<F>>> = Vec::new();
    let mut evaluations = Vec::new();

    // Linear constraint
    // We do these first to benefit from buffer recycling.
    for _ in 0..num_linear_constraints {
        let linear_form = Box::new(Covector {
            vector: (0..num_coeffs).map(F::from).collect(),
        });
        evaluations.push(linear_form.evaluate(&embedding, &vector));
        linear_forms.push(linear_form.clone());
        prove_linear_forms.push(linear_form);
    }

    // Evaluation constraint
    let points: Vec<_> = (0..num_evaluations)
        .map(|x| vec![F::from(x as u64); num_variables])
        .collect();
    for point in &points {
        let linear_form = Box::new(MultilinearExtension::new(point.clone()));
        evaluations.push(linear_form.evaluate(&embedding, &vector));
        linear_forms.push(linear_form.clone());
        prove_linear_forms.push(linear_form);
    }

    let (witness, whir_commit_time) = {
        let _phase = whir::profiling::PhaseGuard::new("commit");
        let start = Instant::now();
        let witness = params.commit(&mut prover_state, &[vector.as_slice()]);
        let elapsed = start.elapsed();
        whir::profiling::record("prover", num_coeffs, "commit_total", elapsed);
        (witness, elapsed)
    };

    let whir_prove_time = {
        let _phase = whir::profiling::PhaseGuard::new("prove");
        let start = Instant::now();
        let _ = params.prove(
            &mut prover_state,
            vec![Cow::Borrowed(&vector)],
            witness,
            prove_linear_forms,
            Cow::Borrowed(&evaluations),
        );
        let elapsed = start.elapsed();
        whir::profiling::record("prover", num_coeffs, "prove_total", elapsed);
        elapsed
    };
    whir::profiling::record(
        "prover",
        num_coeffs,
        "total_prover",
        whir_commit_time + whir_prove_time,
    );

    let proof = prover_state.proof();
    println!(
        "Prover time: {whir_commit_time:.1?} + {whir_prove_time:.1?} = {:.1?}",
        whir_commit_time + whir_prove_time,
    );
    println!(
        "Proof size: {:.1} KiB",
        (proof.narg_string.len() + proof.hints.len()) as f64 / 1024.0
    );

    let weight_dyn_refs = linear_forms
        .iter()
        .map(|w| w.as_ref() as &dyn LinearForm<F>)
        .collect::<Vec<_>>();

    HASH_COUNTER.reset();
    let whir_verifier_time = Instant::now();
    for _ in 0..reps {
        let mut verifier_state = VerifierState::new_std(&ds, &proof);
        let commitment = params.receive_commitments(&mut verifier_state, 1).unwrap();
        params
            .verify(
                &mut verifier_state,
                &weight_dyn_refs,
                &evaluations,
                &commitment,
            )
            .unwrap();
    }
    println!(
        "Verifier time: {:.1?}",
        whir_verifier_time.elapsed() / reps as u32
    );
    println!(
        "Average hashes: {:.1}k",
        (HASH_COUNTER.get() as f64 / reps as f64) / 1000.0
    );
}
