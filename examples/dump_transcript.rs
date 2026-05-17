// ===========================================================================
// dump_transcript.rs — Fiat-Shamir Transcript golden test。
//
// 运行: cargo run --example dump_transcript --release > golden_transcript_rs.txt
// 对拍: diff golden_transcript_rs.txt golden_transcript_cpp.txt
//
// 基于 spongefish::StdHash = instantiations::Shake128 (XOF-based duplex sponge).
// ===========================================================================

use serde::Serialize;
use spongefish::DuplexSpongeInterface;
use whir::transcript::codecs::U64;
use whir::transcript::VerifierMessage;

fn dump_bytes(label: &str, data: &[u8]) {
    print!("  {label} ");
    for byte in data { print!("{byte:02x}"); }
    println!();
}

fn main() {
    #[derive(Serialize)]
    struct TestConfig {
        version: u32,
        field_size: u64,
        security_bits: u32,
    }

    println!("# SECTION transcript");

    // =========================================================================
    // CASE 0: Shake128 海绵基本操作
    // =========================================================================
    {
        println!("CASE 0 sponge-absorb-squeeze");

        let mut sponge = spongefish::instantiations::Shake128::default();
        sponge.absorb(b"hello");
        let mut s0 = [0u8; 32];
        sponge.squeeze(&mut s0);
        dump_bytes("squeeze0", &s0);

        sponge.absorb(b"world");
        let mut s1 = [0u8; 32];
        sponge.squeeze(&mut s1);
        dump_bytes("squeeze1", &s1);

        let mut s2 = [0u8; 16];
        sponge.squeeze(&mut s2);
        dump_bytes("squeeze2_16b", &s2);
    }

    // =========================================================================
    // CASE 1: protocol_id = SHA3-512(cbor(config)), session_id = SHA3-256(cbor(session))
    // =========================================================================
    {
        println!("CASE 1 domain-separator protocol-and-session");

        let config = TestConfig {
            version: 1,
            field_size: 0xFFFFFFFF00000001,
            security_bits: 100,
        };

        use sha3::{Digest, Sha3_256, Sha3_512};
        let mut hash = Sha3_512::new();
        ciborium::into_writer(&config, &mut hash).unwrap();
        let protocol_id: [u8; 64] = hash.finalize().into();
        dump_bytes("protocol_id_h1", &protocol_id[..32]);
        dump_bytes("protocol_id_h2", &protocol_id[32..]);

        let mut hash = Sha3_256::new();
        ciborium::into_writer(&"test_session_42".to_string(), &mut hash).unwrap();
        let session_id: [u8; 32] = hash.finalize().into();
        dump_bytes("session_id", &session_id);
    }

    // =========================================================================
    // CASE 2: ProverState / VerifierState 完整往返
    // =========================================================================
    {
        println!("CASE 2 prover-verifier round-trip");

        let ds = whir::transcript::DomainSeparator::protocol(&0xDEADBEEFu32)
            .session(&"round_trip".to_string())
            .instance(&U64(1024));

        let mut ps = whir::transcript::ProverState::new_std(&ds);
        ps.prover_message(&U64(0xCAFEBABEDEADBEEF));
        ps.prover_message(&U64(0x0123456789ABCDEF));

        let c0: U64 = ps.verifier_message();
        let c1: U64 = ps.verifier_message();
        println!("  challenge0 {:016x}", c0.0);
        println!("  challenge1 {:016x}", c1.0);

        // 用 [u8; 5] 做 hint (spongefish 内置 NargSerialize/NargDeserialize for [u8; N])
        let hint_data: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];
        ps.prover_hint(&hint_data);

        ps.prover_message(&U64(0xFF00FF00FF00FF00));
        let c2: U64 = ps.verifier_message();
        println!("  challenge2 {:016x}", c2.0);

        let proof = ps.proof();
        dump_bytes("proof_narg", &proof.narg_string);
        dump_bytes("proof_hints", &proof.hints);

        // Verifier
        let mut vs = whir::transcript::VerifierState::new_std(&ds, &proof);
        let m0: U64 = vs.prover_message().unwrap();
        let m1: U64 = vs.prover_message().unwrap();
        println!("  message0 {:016x}", m0.0);
        println!("  message1 {:016x}", m1.0);

        let vc0: U64 = vs.verifier_message();
        let vc1: U64 = vs.verifier_message();
        println!("  vchallenge0 {:016x}", vc0.0);
        println!("  vchallenge1 {:016x}", vc1.0);

        let vhint: [u8; 5] = vs.prover_hint().unwrap();
        dump_bytes("vhint", &vhint);

        let m2: U64 = vs.prover_message().unwrap();
        let vc2: U64 = vs.verifier_message();
        println!("  message2 {:016x}", m2.0);
        println!("  vchallenge2 {:016x}", vc2.0);

        let eof = vs.check_eof().is_ok();
        println!("  check_eof {}", eof as i32);
    }

    // =========================================================================
    // CASE 3: Narg 序列化
    // =========================================================================
    {
        println!("CASE 3 narg-serialize vectors");

        use spongefish::NargSerialize;

        // vector<u8> — spongefish Vec<u8> 有 NargSerialize 但没有 NargDeserialize
        // 这里仅序列化验证格式, 对标 C++ narg_serialize
        let orig_u8: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut buf: Vec<u8> = vec![];
        orig_u8.serialize_into_narg(&mut buf);
        dump_bytes("vec_u8_encoded", &buf);

        // vector<U64> — U64 是 WHIR 内置, 有完整 Codec 支持
        let orig_u64 = vec![U64(1), U64(258), U64(0xDEADBEEF)];
        buf.clear();
        orig_u64.serialize_into_narg(&mut buf);
        dump_bytes("vec_u64_encoded", &buf);
        println!("  vec_u64_len {}", orig_u64.len());
        for (i, v) in orig_u64.iter().enumerate() {
            println!("  vec_u64[{i}] {:016x}", v.0);
        }
    }

    // =========================================================================
    // CASE 4: 连续 squeeze 复用同一 XOF reader
    // =========================================================================
    {
        println!("CASE 4 squeeze-streaming xof-reader-reuse");

        let mut sponge_a = spongefish::instantiations::Shake128::default();
        sponge_a.absorb(b"test_xof_streaming");
        let mut all_at_once = [0u8; 40];
        sponge_a.squeeze(&mut all_at_once);
        dump_bytes("squeeze_40b_once", &all_at_once);

        let mut sponge_b = spongefish::instantiations::Shake128::default();
        sponge_b.absorb(b"test_xof_streaming");
        let mut first = [0u8; 20];
        let mut second = [0u8; 20];
        sponge_b.squeeze(&mut first);
        sponge_b.squeeze(&mut second);
        dump_bytes("squeeze_20b_first", &first);
        dump_bytes("squeeze_20b_second", &second);
    }
}
