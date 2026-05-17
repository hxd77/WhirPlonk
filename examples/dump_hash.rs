// ===========================================================================
// dump_hash.rs — 哈希引擎 golden test。
//
// 运行: cargo run --example dump_hash --release > golden_hash_rs.txt
// 覆盖: COPY / BLAKE3 / SHA2 引擎的 hash_many 输出
// ===========================================================================

use whir::engines::EngineId;
use whir::hash::{Hash, BLAKE3, COPY, SHA2, ENGINES};

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

fn main() {
    let mut rng = Lcg::new(0xAAAA_AAAA_AAAA_AAAA);

    let print_hash = |label: &str, h: &Hash| {
        print!("  {label} ");
        for byte in h.0.iter() { print!("{byte:02x}"); }
        println!();
    };

    let make_bytes = |rng: &mut Lcg, n: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let w = rng.next_u64().to_le_bytes();
            for &b in &w { if v.len() < n { v.push(b); } }
        }
        v
    };

    let run = |rng: &mut Lcg, case: usize, engine_id: EngineId, label: &str,
               size: usize, count: usize| {
        let engine = ENGINES.retrieve(engine_id).expect("engine missing");
        let input = make_bytes(rng, size * count);
        let mut output = vec![Hash::default(); count];
        engine.hash_many(size, &input, &mut output);
        println!("CASE {case} {label} size={size} count={count}");
        for (i, h) in output.iter().enumerate() {
            print_hash(&format!("h{i}"), h);
        }
    };

    println!("# SECTION hash");

    // COPY — 恒等映射
    run(&mut rng, 0, COPY, "copy", 0, 2);
    run(&mut rng, 1, COPY, "copy", 16, 2);
    run(&mut rng, 2, COPY, "copy", 32, 3);

    // BLAKE3 — 需要 size 是 64 的倍数
    run(&mut rng, 3, BLAKE3, "blake3", 64, 1);
    run(&mut rng, 4, BLAKE3, "blake3", 64, 4);
    run(&mut rng, 5, BLAKE3, "blake3", 128, 2);
    run(&mut rng, 6, BLAKE3, "blake3", 256, 1);
    run(&mut rng, 7, BLAKE3, "blake3", 1024, 1);

    // SHA2 — 任意大小
    run(&mut rng, 8, SHA2, "sha2", 0, 1);
    run(&mut rng, 9, SHA2, "sha2", 31, 1);
    run(&mut rng, 10, SHA2, "sha2", 32, 3);
    run(&mut rng, 11, SHA2, "sha2", 64, 2);
    run(&mut rng, 12, SHA2, "sha2", 100, 2);
}
