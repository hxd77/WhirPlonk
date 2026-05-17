// ===========================================================================
// dump_ntt.rs — NTT / Wavelet / Transpose golden test。
//
// 运行: cargo run --example dump_ntt --release > golden_ntt_rs.txt
// 覆盖: ntt (数论变换 4/8/16/64 点) + wavelet (小波变换 8/64 点) +
//       transpose (矩阵转置 8×4)
// ===========================================================================

use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use whir::algebra::fields::{Field64, Field64_2, Field64_3};
use whir::algebra::ntt;

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

fn print_base(label: &str, a: Field64) {
    let v: u64 = a.into_bigint().0[0];
    println!("{label} {v}");
}

fn main() {
    let dump_base_vec = |label: &str, v: &[Field64]| {
        println!("  {label} {}", v.len());
        for x in v { print_base("    ", *x); }
    };

    // ========================================================================
    // SECTION ntt (seed: 0x4444...)
    // ========================================================================
    println!("# SECTION ntt");
    {
        let mut rng = Lcg::new(0x4444_4444_4444_4444);
        for (case, n) in [4usize, 8, 16, 64].iter().enumerate() {
            let mut values: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            ntt::ntt(&mut values);
            println!("CASE {case} ntt n={n}");
            dump_base_vec("out", &values);
        }
    }

    // ========================================================================
    // SECTION wavelet (seed: 0x5555...)
    // ========================================================================
    println!("# SECTION wavelet");
    {
        let mut rng = Lcg::new(0x5555_5555_5555_5555);
        for (case, n) in [8usize, 64].iter().enumerate() {
            let mut values: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            ntt::wavelet_transform(&mut values);
            println!("CASE {case} wavelet n={n}");
            dump_base_vec("out", &values);
        }
    }

    // ========================================================================
    // SECTION transpose (seed: 0x6666...)
    // ========================================================================
    println!("# SECTION transpose");
    {
        let mut rng = Lcg::new(0x6666_6666_6666_6666);
        let rows = 8usize; let cols = 4usize;
        let mut m: Vec<u64> = (0..rows * cols).map(|_| rng.next_u64()).collect();
        ntt::transpose(&mut m, rows, cols);
        println!("CASE 0 transpose 8x4");
        for v in &m { println!("  {v}"); }
    }
}
