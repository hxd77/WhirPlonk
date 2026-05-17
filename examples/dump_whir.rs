// ===========================================================================
// dump_whir.rs — WHIR 协议 golden test (跨语言对拍基准, 多 case)
//
// 运行: cargo run --example dump_whir --release > golden_whir_rs.txt
// 对拍: diff golden_whir_rs.txt golden_whir_cpp.txt
//
// Case 覆盖:
//   CASE 0: 1 多项式 × 2 系数  (最小可用)
//   CASE 1: 1 多项式 × 4 系数
//   CASE 2: 1 多项式 × 8 系数
//   CASE 3: 3 多项式 × 4 系数  (多向量)
//   CASE 4: 4 多项式 × 8 系数  (多向量, 大参数)
// ===========================================================================

use std::borrow::Cow;

use ark_ff::Field;
use ordered_float::OrderedFloat;

use whir::algebra::{
    embedding::Identity,
    fields::Field64,
    linear_form::{Covector, LinearForm},
};
use whir::hash::SHA2;
use whir::protocols::{
    irs_commit, matrix_commit, merkle_tree, proof_of_work, sumcheck,
    whir as whir_mod,
};
use whir::transcript::{
    codecs::Empty, DomainSeparator, ProverState, VerifierMessage, VerifierState,
};

type F = Field64;

fn dump_bytes(label: &str, data: &[u8]) {
    print!("    {label} ");
    for byte in data { print!("{byte:02x}"); }
    println!();
}

fn dump_field_vec(label: &str, vec: &[F]) {
    print!("    {label}");
    for v in vec { print!(" {v}"); }
    println!();
}

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn next_field64(&mut self) -> F { F::from(self.next_u64()) }
}

/// 为每个 case 构造独立的 DomainSeparator (session 不同, 区分海绵状态)
fn make_ds(label: &str) -> DomainSeparator<'static, Empty> {
    let session_str = format!("whir_{label}");
    DomainSeparator::protocol(&0xBEEFu32)
        .session(&session_str)
        .instance(&Empty)
}

/// 运行单个 WHIR 测试 case
fn run_case(
    case_id: usize,
    num_vectors: usize,
    vector_size: usize,
    rng: &mut Lcg,
) {
    let depth: usize = 1;
    let cw = vector_size * 2;
    let num_cols = num_vectors * depth;
    let ood = 1usize;
    let ind = 3.min(vector_size);
    let log_vs = vector_size.ilog2() as usize;

    println!("CASE {case_id}");

    // ---- 1. 输入构造 ----
    // 每个多项式生成随机系数
    let mut vecs: Vec<Vec<F>> = Vec::with_capacity(num_vectors);
    let mut evals = Vec::with_capacity(num_vectors);
    for vi in 0..num_vectors {
        let v: Vec<F> = (0..vector_size).map(|_| rng.next_field64()).collect();
        dump_field_vec(&format!("input_vector{vi}"), &v);
        evals.push(v.iter().sum());  // 全 1 线性形式在每向量上的求值 = sum(coeffs)
        vecs.push(v);
    }
    let vec_slices: Vec<&[F]> = vecs.iter().map(|v| v.as_slice()).collect();

    // 一个全 1 线性形式, 对每个多项式做一个求值
    let cv = (0..vector_size).map(|_| F::ONE).collect::<Vec<_>>();
    let lfs: Vec<Box<dyn LinearForm<F>>> =
        vec![Box::new(Covector { vector: cv })];

    // ---- 2. 协议配置 ----
    let mt = merkle_tree::Config::with_hash(SHA2, cw);
    let irs = irs_commit::Config::<Identity<F>> {
        embedding: Default::default(),
        num_vectors,
        vector_size,
        codeword_length: cw,
        interleaving_depth: depth,
        matrix_commit: matrix_commit::Config::<F> {
            element_type: Default::default(),
            num_cols,
            leaf_hash_id: SHA2,
            merkle_tree: mt,
        },
        johnson_slack: OrderedFloat(0.0),
        in_domain_samples: ind,
        out_domain_samples: ood,
        deduplicate_in_domain: false,
    };

    let sc_init = sumcheck::Config::<F> {
        field: Default::default(),
        initial_size: vector_size,
        round_pow: proof_of_work::Config { hash_id: SHA2, threshold: u64::MAX },
        num_rounds: 0,
    };
    let skip_pow = proof_of_work::Config { hash_id: SHA2, threshold: u64::MAX };
    let sc_final = sumcheck::Config::<F> {
        field: Default::default(),
        initial_size: vector_size,
        round_pow: proof_of_work::Config { hash_id: SHA2, threshold: u64::MAX },
        num_rounds: log_vs,
    };

    let whir_config = whir_mod::Config::<Identity<F>> {
        initial_committer: irs,
        initial_sumcheck: sc_init,
        initial_skip_pow: skip_pow,
        round_configs: vec![],
        final_sumcheck: sc_final,
        final_pow: proof_of_work::Config { hash_id: SHA2, threshold: u64::MAX },
    };

    // ---- 3. DomainSeparator ----
    let ds = make_ds(&case_id.to_string());

    // ---- 4. Prover ----
    let mut ps = ProverState::new_std(&ds);
    let witness = whir_config.commit(&mut ps, &vec_slices);

    dump_field_vec("witness_matrix", &witness.matrix);
    dump_field_vec("ood_points", &witness.out_of_domain.points);
    dump_field_vec("ood_matrix", &witness.out_of_domain.matrix);

    let witnesses: Vec<Cow<irs_commit::Witness<F, F>>> = vec![Cow::Owned(witness)];
    let vec_cows: Vec<Cow<[F]>> = vec_slices.iter().map(|v| Cow::Borrowed(*v)).collect();

    let claim = whir_config.prove(
        &mut ps, vec_cows, witnesses,
        lfs, Cow::Borrowed(&evals),
    );
    let proof = ps.proof();

    dump_field_vec("eval_point", &claim.evaluation_point);
    dump_field_vec("rlc_coeffs", &claim.rlc_coefficients);
    dump_bytes("proof_narg", &proof.narg_string);
    dump_bytes("proof_hints", &proof.hints);

    // ---- 5. Verifier ----
    let mut vs = VerifierState::new_std(&ds, &proof);
    let comm = whir_config.receive_commitment(&mut vs).unwrap();
    let vc = whir_config.verify(&mut vs, &[&comm], &evals).unwrap();

    dump_field_vec("v_eval_point", &vc.evaluation_point);
    dump_field_vec("v_rlc_coeffs", &vc.rlc_coefficients);
    println!("    check_eof {}", vs.check_eof().is_ok() as i32);
}

fn main() {
    let mut rng = Lcg::new(0xCAFE);
    println!("# SECTION whir");

    // CASE 0: 1 多项式 × 2 系数 (最小)
    run_case(0, 1, 2, &mut rng);

    // CASE 1: 1 多项式 × 4 系数
    run_case(1, 1, 4, &mut rng);

    // CASE 2: 1 多项式 × 8 系数
    run_case(2, 1, 8, &mut rng);

    // CASE 3: 3 多项式 × 4 系数 (多向量)
    run_case(3, 3, 4, &mut rng);

    // CASE 4: 4 多项式 × 8 系数 (多向量 + 大参数)
    run_case(4, 4, 8, &mut rng);
}
