// ===========================================================================
// dump_matrix_commit.rs — 矩阵承诺 golden test。
//
// 运行: cargo run --example dump_matrix_commit --release > golden_mcommit_rs.txt
// 覆盖: Field64/Field64_2/Field64_3 的 LE 编码 + 行哈希 (BLAKE3/SHA2/COPY)
// ===========================================================================

use whir::algebra::fields::{Field64, Field64_2, Field64_3};
use whir::hash::{Hash, BLAKE3, COPY, SHA2, ENGINES};
use whir::protocols::matrix_commit::Encodable;

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

fn main() {
    let mut rng = Lcg::new(0xBBBB_BBBB_BBBB_BBBB);

    let dump_hash = |label: &str, h: &Hash| {
        print!("  {label} ");
        for byte in h.0.iter() { print!("{byte:02x}"); }
        println!();
    };

    println!("# SECTION matrix_commit");

    // CASE 0: Field64, Blake3, 4 rows × 8 cols (msg_size = 8*8 = 64)
    {
        let nr = 4usize; let nc = 8usize; let ms = Field64::encoded_size() * nc;
        let matrix: Vec<Field64> = (0..nr*nc).map(|_| Field64::from(rng.next_u64())).collect();
        let mut encoder = Field64::encoder(); let bytes = encoder.encode(&matrix);
        let engine = ENGINES.retrieve(BLAKE3).expect("engine");
        let mut leaves = vec![Hash::default(); nr];
        engine.hash_many(ms, bytes, &mut leaves);
        println!("CASE 0 field64-blake3 rows={nr} cols={nc} msg_size={ms}");
        for (i, h) in leaves.iter().enumerate() { dump_hash(&format!("leaf{i}"), h); }
    }

    // CASE 1: Field64_2, Blake3, 2 rows × 8 cols (msg_size = 16*8 = 128)
    {
        let nr = 2usize; let nc = 8usize; let ms = Field64_2::encoded_size() * nc;
        let matrix: Vec<Field64_2> = (0..nr*nc)
            .map(|_| Field64_2::new(Field64::from(rng.next_u64()), Field64::from(rng.next_u64())))
            .collect();
        let mut encoder = Field64_2::encoder(); let bytes = encoder.encode(&matrix);
        let engine = ENGINES.retrieve(BLAKE3).expect("engine");
        let mut leaves = vec![Hash::default(); nr];
        engine.hash_many(ms, bytes, &mut leaves);
        println!("CASE 1 field64_2-blake3 rows={nr} cols={nc} msg_size={ms}");
        for (i, h) in leaves.iter().enumerate() { dump_hash(&format!("leaf{i}"), h); }
    }

    // CASE 2: Field64_3, Sha2, 3 rows × 5 cols (msg_size = 24*5 = 120)
    {
        let nr = 3usize; let nc = 5usize; let ms = Field64_3::encoded_size() * nc;
        let matrix: Vec<Field64_3> = (0..nr*nc)
            .map(|_| Field64_3::new(Field64::from(rng.next_u64()), Field64::from(rng.next_u64()), Field64::from(rng.next_u64())))
            .collect();
        let mut encoder = Field64_3::encoder(); let bytes = encoder.encode(&matrix);
        let engine = ENGINES.retrieve(SHA2).expect("engine");
        let mut leaves = vec![Hash::default(); nr];
        engine.hash_many(ms, bytes, &mut leaves);
        println!("CASE 2 field64_3-sha2 rows={nr} cols={nc} msg_size={ms}");
        for (i, h) in leaves.iter().enumerate() { dump_hash(&format!("leaf{i}"), h); }
    }

    // CASE 3: Field64, Sha2, 2 rows × 4 cols (msg_size = 8*4 = 32)
    {
        let nr = 2usize; let nc = 4usize; let ms = Field64::encoded_size() * nc;
        let matrix: Vec<Field64> = (0..nr*nc).map(|_| Field64::from(rng.next_u64())).collect();
        let mut encoder = Field64::encoder(); let bytes = encoder.encode(&matrix);
        let engine = ENGINES.retrieve(SHA2).expect("engine");
        let mut leaves = vec![Hash::default(); nr];
        engine.hash_many(ms, bytes, &mut leaves);
        println!("CASE 3 field64-sha2 rows={nr} cols={nc} msg_size={ms}");
        for (i, h) in leaves.iter().enumerate() { dump_hash(&format!("leaf{i}"), h); }
    }

    // CASE 4: Field64, Copy, 3 rows × 4 cols (msg_size = 32)
    {
        let nr = 3usize; let nc = 4usize; let ms = Field64::encoded_size() * nc;
        let matrix: Vec<Field64> = (0..nr*nc).map(|_| Field64::from(rng.next_u64())).collect();
        let mut encoder = Field64::encoder(); let bytes = encoder.encode(&matrix);
        let engine = ENGINES.retrieve(COPY).expect("engine");
        let mut leaves = vec![Hash::default(); nr];
        engine.hash_many(ms, bytes, &mut leaves);
        println!("CASE 4 field64-copy rows={nr} cols={nc} msg_size={ms}");
        for (i, h) in leaves.iter().enumerate() { dump_hash(&format!("leaf{i}"), h); }
    }
}
