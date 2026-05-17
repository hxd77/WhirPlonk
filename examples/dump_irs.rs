// ===========================================================================
// dump_irs.rs — IRS 承诺协议 golden test。
//
// 运行: cargo run --example dump_irs --release > golden_irs_rs.txt
// 对拍: diff golden_irs_rs.txt golden_irs_cpp.txt
//
// 测试: IRS commit → receive_commitment → open → verify 完整周期。
// 最小参数: 1 vector × 4 coeffs, interleaving_depth=1, rate=0.5
// ===========================================================================

use ark_ff::{AdditiveGroup, Zero};
use whir::algebra::{
    embedding::Identity,
    fields::Field64,
    ntt::interleaved_rs_encode,
};
use whir::hash::{SHA2, Hash};
use whir::protocols::{
    irs_commit,
    matrix_commit,
    merkle_tree,
};
fn dump_bytes(label: &str, data: &[u8]) {
    print!("  {label} ");
    for byte in data { print!("{byte:02x}"); }
    println!();
}

fn dump_hashes(label: &str, hashes: &[Hash]) {
    print!("  {label} ");
    for h in hashes { for b in h.0 { print!("{b:02x}"); } }
    println!();
}

fn dump_field_vec(label: &str, vec: &[Field64]) {
    print!("  {label}");
    for v in vec { print!(" {}", v); }
    println!();
}

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn next_field64(&mut self) -> Field64 { Field64::from(self.next_u64()) }
}

fn main() {
    type F = Field64;
    let mut rng = Lcg::new(0xDEAD_BEEF_CAFE_BABE);

    let num_vectors: usize = 1;
    let vector_size: usize = 4;
    let interleaving_depth: usize = 1;
    let message_length = vector_size / interleaving_depth;
    let codeword_length: usize = 8;  // rate = 4/8 = 0.5
    let in_domain_samples: usize = 2;
    let out_domain_samples: usize = 1;

    // 确定性输入向量
    let vectors: Vec<Vec<F>> = (0..num_vectors)
        .map(|_| (0..vector_size).map(|_| rng.next_field64()).collect())
        .collect();
    let vec_slices: Vec<&[F]> = vectors.iter().map(|v| v.as_slice()).collect();

    println!("# SECTION irs_commit");

    // 打印输入向量
    for (i, v) in vectors.iter().enumerate() {
        dump_field_vec(&format!("input_vector{i}"), v);
    }

    // ---- 编码矩阵 (interleaved RS encode) ----
    let matrix = interleaved_rs_encode(&vec_slices, codeword_length, interleaving_depth);
    let num_cols = num_vectors * interleaving_depth;
    println!("CASE 0 rs-encoded-matrix rows={} cols={}", codeword_length, num_cols);
    dump_field_vec("matrix", &matrix);

    // ---- 叶子哈希 (commit_leaves) ----
    let engine = whir::hash::ENGINES.retrieve(SHA2).expect("engine");
    let mut leaves = vec![Hash::default(); codeword_length];
    let message_size = <F as matrix_commit::Encodable>::encoded_size() * num_cols;
    let mut encoder = <F as matrix_commit::Encodable>::encoder();
    let bytes = encoder.encode(&matrix);
    engine.hash_many(message_size, bytes, &mut leaves);
    println!("CASE 1 leaf-hashes msg_size={}", message_size);
    dump_hashes("leaves", &leaves);

    // ---- 完整协议 (C++/Rust DomainSeparator 差异, 仅验证核心计算) ----
    println!("CASE 2 full-protocol-cpp-compat");

    // 手动计算 protocol_id / session_id (与 C++ 完全一致的 CBOR 字节)
    use sha3::{Digest, Sha3_256, Sha3_512};
    let mut h = Sha3_512::new();
    ciborium::into_writer(&0xBEEFu32, &mut h).unwrap();
    let pid: [u8; 64] = h.finalize().into();
    let mut h = Sha3_256::new();
    ciborium::into_writer(&"irs_dump".to_string(), &mut h).unwrap();
    let sid: [u8; 32] = h.finalize().into();

    // 构造 WHIR Config (用于 commit_leaves + Merkle tree 等核心计算)
    let mt_config = merkle_tree::Config::with_hash(SHA2, codeword_length);
    let mc_config = matrix_commit::Config {
        element_type: Default::default(),
        num_cols,
        leaf_hash_id: SHA2,
        merkle_tree: mt_config,
    };

    let config = irs_commit::Config::<Identity<F>> {
        embedding: Default::default(),
        num_vectors,
        vector_size,
        codeword_length,
        interleaving_depth,
        matrix_commit: mc_config,
        johnson_slack: Default::default(),
        in_domain_samples,
        out_domain_samples,
        deduplicate_in_domain: false,
    };

    // 使用 spongefish 直接构造 DomainSeparator (与 C++ 一致)
    // new(pid) → DomainSeparator<WithoutInstance<u8>, [u8; 64]>
    // .session(sid) → S 推断为 [u8; 32], 匹配 WHIR 端行为
    let ds = spongefish::DomainSeparator::new(pid)
        .session(sid);
    let instance: Vec<u8> = vec![];  // empty instance → 0 字节吸收
    let ds_inst = ds.instance(&instance);

    // Prover
    let mut ps = ds_inst.std_prover();
    let witness = config.commit(&mut ps, &vec_slices);
    let in_domain_evals = config.open(&mut ps, &[&witness]);
    let proof = ps.proof();

    dump_field_vec("witness_matrix", &witness.matrix);
    dump_field_vec("ood_points", &witness.out_of_domain.points);
    dump_field_vec("ood_matrix", &witness.out_of_domain.matrix);
    dump_field_vec("indomain_points", &in_domain_evals.points);
    dump_field_vec("indomain_matrix", &in_domain_evals.matrix);
    dump_bytes("proof_narg", &proof.narg_string);
    dump_bytes("proof_hints", &proof.hints);

    // Verifier
    let mut vs = ds_inst.std_verifier(&proof.narg_string);
    let commitment = config.receive_commitment(&mut vs).unwrap();
    let verifier_evals = config.verify(&mut vs, &[&commitment]).unwrap();

    let ood = commitment.out_of_domain();
    dump_field_vec("v_ood_points", &ood.points);
    dump_field_vec("v_ood_matrix", &ood.matrix);
    dump_field_vec("v_indomain_points", &verifier_evals.points);
    dump_field_vec("v_indomain_matrix", &verifier_evals.matrix);
    let eof = vs.check_eof().is_ok();
    println!("  check_eof {}", eof as i32);
}
