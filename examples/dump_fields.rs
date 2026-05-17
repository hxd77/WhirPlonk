// ===========================================================================
// dump_fields.rs — Goldilocks 基域及扩域运算 golden test。
//
// 运行: cargo run --example dump_fields --release > golden_fields_rs.txt
// 覆盖: Fp (base) / Fp2 (ext2) / Fp3 (ext3) 的加减乘、平方、求逆、Frobenius
// ===========================================================================

use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use whir::algebra::fields::{Field64, Field64_2, Field64_3};

// ===========================================================================
// LCG — 线性同余生成器 (与 C++ 侧完全一致)
// 公式: X_{n+1} = (6364136223846793005 * X_n + 1442695040888963407) mod 2^64
// 种子: 0xCAFEBABE_DEADBEEF
// ===========================================================================
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

/// Field64 内部是 Montgomery 形式，into_bigint() 还原为标准 u64。
fn print_base(label: &str, a: Field64) {
    let v: u64 = a.into_bigint().0[0];
    println!("{label} {v}");
}
fn print_ext2(label: &str, a: Field64_2) {
    let c0: u64 = a.c0.into_bigint().0[0];
    let c1: u64 = a.c1.into_bigint().0[0];
    println!("{label} {c0} {c1}");
}
fn print_ext3(label: &str, a: Field64_3) {
    let c0: u64 = a.c0.into_bigint().0[0];
    let c1: u64 = a.c1.into_bigint().0[0];
    let c2: u64 = a.c2.into_bigint().0[0];
    println!("{label} {c0} {c1} {c2}");
}

fn main() {
    let mut rng = Lcg::new(0xCAFEBABE_DEADBEEF);

    // ========================================================================
    // SECTION base — Fp 基域 (p = 2^64 - 2^32 + 1)
    // ========================================================================
    println!("# SECTION base");
    for i in 0..3 {
        let a_raw = rng.next_u64();
        let b_raw = rng.next_u64();
        let a = Field64::from(a_raw);
        let b = Field64::from(b_raw);
        println!("CASE {i} {a_raw} {b_raw}");
        print_base("  add", a + b);
        print_base("  sub", a - b);
        print_base("  neg", -a);
        print_base("  mul", a * b);
        print_base("  sq",  a.square());
        if !a.is_zero() { print_base("  inv", a.inverse().unwrap()); }
        print_base("  pow10", a.pow([10u64]));
    }

    // ========================================================================
    // SECTION ext2 — Fp2 = Fp[X] / (X² - 7)
    // ========================================================================
    println!("\n# SECTION ext2");
    for i in 0..3 {
        let a0 = rng.next_u64(); let a1 = rng.next_u64();
        let b0 = rng.next_u64(); let b1 = rng.next_u64();
        let a = Field64_2::new(Field64::from(a0), Field64::from(a1));
        let b = Field64_2::new(Field64::from(b0), Field64::from(b1));
        println!("CASE {i} {a0} {a1} {b0} {b1}");
        print_ext2("  add", a + b);
        print_ext2("  sub", a - b);
        print_ext2("  mul", a * b);
        print_ext2("  sq",  a.square());
        if !a.is_zero() { print_ext2("  inv", a.inverse().unwrap()); }
        print_ext2("  frob1", a.frobenius_map(1));
    }

    // ========================================================================
    // SECTION ext3 — Fp3 = Fp[X] / (X³ - 2)
    // ========================================================================
    println!("\n# SECTION ext3");
    for i in 0..3 {
        let a0 = rng.next_u64(); let a1 = rng.next_u64(); let a2 = rng.next_u64();
        let b0 = rng.next_u64(); let b1 = rng.next_u64(); let b2 = rng.next_u64();
        let a = Field64_3::new(Field64::from(a0), Field64::from(a1), Field64::from(a2));
        let b = Field64_3::new(Field64::from(b0), Field64::from(b1), Field64::from(b2));
        println!("CASE {i} {a0} {a1} {a2} {b0} {b1} {b2}");
        print_ext3("  add", a + b);
        print_ext3("  sub", a - b);
        print_ext3("  mul", a * b);
        print_ext3("  sq",  a.square());
        if !a.is_zero() { print_ext3("  inv", a.inverse().unwrap()); }
        print_ext3("  frob1", a.frobenius_map(1));
    }
}
