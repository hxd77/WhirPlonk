// ===========================================================================
// dump_pow.rs — Proof of Work golden test。
//
// 运行: cargo run --example dump_pow --release > golden_pow_rs.txt
// 覆盖: BLAKE3/SHA2 引擎的 nonce 查找 (难度 2^60, 即 4 bits)
// ===========================================================================

use whir::engines::EngineId;
use whir::hash::{Hash, BLAKE3, SHA2, ENGINES};
use zerocopy::IntoBytes;

fn main() {
    let dump_hash = |label: &str, h: &Hash| {
        print!("  {label} ");
        for byte in h.0.iter() { print!("{byte:02x}"); }
        println!();
    };

    println!("# SECTION pow");
    let cases: &[(&str, EngineId, u64, [u8; 32])] = &[
        ("blake3-thr60bits", BLAKE3, 1u64 << 60, [0xAA; 32]),
        ("sha2-thr60bits",   SHA2,   1u64 << 60, [0x55; 32]),
    ];
    for (case_idx, &(label, hash_id, threshold, challenge)) in cases.iter().enumerate() {
        let engine = ENGINES.retrieve(hash_id).expect("engine");
        let batch = engine.preferred_batch_size().max(1);
        let mut inputs = vec![[0u8; 64]; batch];
        for inp in &mut inputs { inp[..32].copy_from_slice(&challenge); }
        let mut outputs = vec![Hash::default(); batch];
        let mut found_nonce: Option<u64> = None;
        'outer: for base in (0u64..).step_by(batch) {
            for (i, inp) in inputs.iter_mut().enumerate() {
                inp[32..40].copy_from_slice(&(base + i as u64).to_le_bytes());
            }
            engine.hash_many(64, inputs.as_bytes(), &mut outputs);
            for (i, out) in outputs.iter().enumerate() {
                if u64::from_le_bytes(out.0[..8].try_into().unwrap()) <= threshold {
                    found_nonce = Some(base + i as u64); break 'outer;
                }
            }
        }
        let nonce = found_nonce.expect("PoW must find a nonce");
        let mut single = [0u8; 64];
        single[..32].copy_from_slice(&challenge);
        single[32..40].copy_from_slice(&nonce.to_le_bytes());
        let mut single_out = [Hash::default(); 1];
        engine.hash_many(64, &single, &mut single_out);
        println!("CASE {case_idx} {label} threshold={threshold}");
        println!("  nonce {nonce}");
        dump_hash("hash", &single_out[0]);
    }
}
