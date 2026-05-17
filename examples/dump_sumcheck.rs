// ===========================================================================
// dump_sumcheck.rs — Sumcheck 协议 golden test。
//
// 运行: cargo run --example dump_sumcheck --release > golden_sumcheck_rs.txt
// 对拍: diff golden_sumcheck_rs.txt golden_sumcheck_cpp.txt
//
// 手动构造 sponge 输入 (protocol_id/session_id/c0/c2), 绕过 WHIR DomainSeparator
// 的内部 CBOR map 序列化差异, 确保与 C++ 端字节级对拍。
// ===========================================================================

use ark_ff::{AdditiveGroup, PrimeField, Zero};
use sha3::{Digest, Sha3_256, Sha3_512};
use spongefish::DuplexSpongeInterface;
use whir::algebra::fields::Field64;
use whir::algebra::sumcheck::{compute_sumcheck_polynomial, fold};
use whir::transcript::codecs::U64;

fn dump_bytes(label: &str, data: &[u8]) {
    print!("  {label} ");
    for byte in data { print!("{byte:02x}"); }
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
    let mut rng = Lcg::new(0xAAAABBBBCCCCDDDDu64);

    let initial_size = 8usize;
    let num_rounds = 3usize;

    let a: Vec<Field64> = (0..initial_size).map(|_| rng.next_field64()).collect();
    let b: Vec<Field64> = (0..initial_size).map(|_| rng.next_field64()).collect();

    println!("# SECTION sumcheck");
    print!("  vector_a");
    for v in &a { print!(" {}", v); }
    println!();
    print!("  vector_b");
    for v in &b { print!(" {}", v); }
    println!();

    let mut sum = Field64::zero();
    for i in 0..initial_size { sum += a[i] * b[i]; }
    println!("  initial_sum {}", sum);

    // ---- 构造 sponge 输入 (与 C++ 端完全一致的显式字节) ----
    // protocol_id = SHA3-512(cbor(0xABCD)) = SHA3-512([19 AB CD])
    let mut h = Sha3_512::new();
    ciborium::into_writer(&0xABCDu32, &mut h).unwrap();
    let pid: [u8; 64] = h.finalize().into();

    // session_id = SHA3-256(cbor("sumcheck_dump")) = SHA3-256([6D + 14 bytes])
    let mut h = Sha3_256::new();
    ciborium::into_writer(&"sumcheck_dump".to_string(), &mut h).unwrap();
    let sid: [u8; 32] = h.finalize().into();

    // ---- Prover ----
    let mut a_prove = a.clone();
    let mut b_prove = b.clone();
    let mut sum_prove = sum;

    // 手动模拟 WHIR ProverState: sponge + narg
    let mut sponge = spongefish::instantiations::Shake128::default();
    let mut narg_buf: Vec<u8> = vec![];

    // absorb DomainSeparator
    sponge.absorb(&pid);
    sponge.absorb(&sid);

    println!("CASE 0 sumcheck prove");

    for round in 0..num_rounds {
        let (c0, c2) = compute_sumcheck_polynomial(&a_prove, &b_prove);
        println!("  round{round}_c0 {}", c0);
        println!("  round{round}_c2 {}", c2);

        // prover_message(c0): encode → absorb → narg
        let c0_bytes = c0.into_bigint().as_ref()[0].to_le_bytes();
        sponge.absorb(&c0_bytes);
        use spongefish::NargSerialize;
        U64(c0.into_bigint().as_ref()[0]).serialize_into_narg(&mut narg_buf);

        // prover_message(c2): encode → absorb → narg
        let c2_bytes = c2.into_bigint().as_ref()[0].to_le_bytes();
        sponge.absorb(&c2_bytes);
        U64(c2.into_bigint().as_ref()[0]).serialize_into_narg(&mut narg_buf);

        // verifier_message<Field64>
        let mut r_bytes = [0u8; 8];
        sponge.squeeze(&mut r_bytes);
        let r = Field64::from(u64::from_le_bytes(r_bytes));
        println!("  round{round}_r {}", r);

        fold(&mut a_prove, r);
        fold(&mut b_prove, r);
        let c1 = sum_prove - c0.double() - c2;
        sum_prove = (c2 * r + c1) * r + c0;
        println!("  round{round}_sum {}", sum_prove);
    }

    println!("CASE 1 final vectors");
    print!("  final_a");
    for v in &a_prove { print!(" {}", v); }
    println!();
    print!("  final_b");
    for v in &b_prove { print!(" {}", v); }
    println!();

    dump_bytes("proof_narg", &narg_buf);

    // ---- Verifier ----
    let mut vs_sponge = spongefish::instantiations::Shake128::default();
    vs_sponge.absorb(&pid);
    vs_sponge.absorb(&sid);

    use spongefish::NargDeserialize;
    let mut narg_cursor: &[u8] = &narg_buf;
    let mut sum_verify = sum;

    println!("CASE 2 sumcheck verify");

    for round in 0..num_rounds {
        // prover_message: deserialize → absorb
        let c0u = U64::deserialize_from_narg(&mut narg_cursor).unwrap();
        let c0 = Field64::from(c0u.0);
        let c2u = U64::deserialize_from_narg(&mut narg_cursor).unwrap();
        let c2 = Field64::from(c2u.0);

        vs_sponge.absorb(&c0u.0.to_le_bytes());
        vs_sponge.absorb(&c2u.0.to_le_bytes());

        println!("  round{round}_c0 {}", c0);
        println!("  round{round}_c2 {}", c2);

        let mut r_bytes = [0u8; 8];
        vs_sponge.squeeze(&mut r_bytes);
        let r = Field64::from(u64::from_le_bytes(r_bytes));
        println!("  round{round}_r {}", r);

        let c1 = sum_verify - c0.double() - c2;
        sum_verify = (c2 * r + c1) * r + c0;
        println!("  round{round}_sum {}", sum_verify);
    }

    let eof = narg_cursor.is_empty();
    println!("  check_eof {}", eof as i32);
}
