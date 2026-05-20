// ===========================================================================
// dump_sumcheck.cpp — Sumcheck 协议 golden test。
//
// 运行: ./dump_sumcheck > golden_sumcheck_cpp.txt
// 对拍: diff golden_sumcheck_rs.txt golden_sumcheck_cpp.txt
//
// 测试: sumcheck prove → verify 完整周期, 与 Rust 端字节级对拍。
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/sumcheck.hpp"
#include "whir/protocols/proof_of_work.hpp"
#include "whir/protocols/sumcheck_protocol.hpp"
#include "whir/transcript/transcript.hpp"

#include <cstdint>
#include <cstdio>
#include <vector>

using F = ::whir::algebra::Goldilocks;

// LCG — 与 Rust 侧完全一致
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

// 打印 Goldilocks 值为十进制 u64 (匹配 Rust Display)
void print_f(const char* label, F v) {
    std::printf("  %s %llu\n", label, (unsigned long long)v.as_canonical_u64());
}

// 十六进制打印字节数组
template <typename T>
void dump_bytes(const char* label, const T& data) {
    std::printf("  %s ", label);
    for (auto byte : data) std::printf("%02x", static_cast<unsigned>(byte));
    std::printf("\n");
}

int main() {
    Lcg rng(0xAAAABBBBCCCCDDDDULL);

    const std::size_t initial_size = 8;  // 2^3 = 8
    const std::size_t num_rounds = 3;

    // 确定性向量
    std::vector<F> a(initial_size);
    std::vector<F> b(initial_size);
    for (std::size_t i = 0; i < initial_size; ++i) a[i] = F::from_u64(rng.next());
    for (std::size_t i = 0; i < initial_size; ++i) b[i] = F::from_u64(rng.next());

    std::printf("# SECTION sumcheck\n");

    std::printf("  vector_a");
    for (auto& v : a) std::printf(" %llu", (unsigned long long)v.as_canonical_u64());
    std::printf("\n");
    std::printf("  vector_b");
    for (auto& v : b) std::printf(" %llu", (unsigned long long)v.as_canonical_u64());
    std::printf("\n");

    // 内积 sum_i a[i]*b[i]
    F sum = F::zero();
    for (std::size_t i = 0; i < initial_size; ++i) sum += a[i] * b[i];
    std::printf("  initial_sum %llu\n", (unsigned long long)sum.as_canonical_u64());

    // Config
    ::whir::protocols::sumcheck::Config<F> config;
    config.initial_size = initial_size;
    config.num_rounds = num_rounds;
    config.round_pow = ::whir::protocols::pow::PowConfig{};

    // 手动计算 protocol_id / session_id (与 Rust 一致)
    ::whir::transcript::DomainSeparator ds;
    {
        uint8_t cbor_proto[] = {0x19, 0xAB, 0xCD};
        sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
        uint8_t cbor_sess[] = {0x6D, 0x73, 0x75, 0x6D, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x5F, 0x64, 0x75, 0x6D, 0x70};
        sha3_256_hash(cbor_sess, 14, ds.session_id.data());
    }

    // ---- Prover ----
    auto a_prove = a;
    auto b_prove = b;
    F sum_prove = sum;

    ::whir::transcript::Empty instance;
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);

    std::printf("CASE 0 sumcheck prove\n");

    for (std::size_t round = 0; round < num_rounds; ++round) {
        // 计算 sumcheck 多项式系数 c0, c2
        auto [c0, c2] = ::whir::algebra::compute_sumcheck_polynomial<F>(a_prove, b_prove);
        print_f((std::string("round") + std::to_string(round) + "_c0").c_str(), c0);
        print_f((std::string("round") + std::to_string(round) + "_c2").c_str(), c2);

        ps.prover_message(c0);
        ps.prover_message(c2);

        F r = ps.template verifier_message<F>();
        print_f((std::string("round") + std::to_string(round) + "_r").c_str(), r);

        // 折叠向量: a, b 各压缩一半
        ::whir::algebra::fold<F>(a_prove, r);
        ::whir::algebra::fold<F>(b_prove, r);
        // c1 = sum - 2*c0 - c2, 新 sum = c(r)
        F c1 = sum_prove - (c0 + c0) - c2;
        sum_prove = (c2 * r + c1) * r + c0;
        print_f((std::string("round") + std::to_string(round) + "_sum").c_str(), sum_prove);
    }

    // 最终向量
    std::printf("CASE 1 final vectors\n");
    std::printf("  final_a");
    for (auto& v : a_prove) std::printf(" %llu", (unsigned long long)v.as_canonical_u64());
    std::printf("\n");
    std::printf("  final_b");
    for (auto& v : b_prove) std::printf(" %llu", (unsigned long long)v.as_canonical_u64());
    std::printf("\n");

    auto proof = std::move(ps).proof();
    dump_bytes("proof_narg", proof.narg_string);

    // ---- Verifier ----
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    F sum_verify = sum;

    std::printf("CASE 2 sumcheck verify\n");

    for (std::size_t round = 0; round < num_rounds; ++round) {
        F c0, c2;
        vs.prover_message(c0);
        vs.prover_message(c2);
        print_f((std::string("round") + std::to_string(round) + "_c0").c_str(), c0);
        print_f((std::string("round") + std::to_string(round) + "_c2").c_str(), c2);

        F r = vs.template verifier_message<F>();
        print_f((std::string("round") + std::to_string(round) + "_r").c_str(), r);

        F c1 = sum_verify - (c0 + c0) - c2;
        sum_verify = (c2 * r + c1) * r + c0;
        print_f((std::string("round") + std::to_string(round) + "_sum").c_str(), sum_verify);
    }

    bool eof = vs.check_eof();
    std::printf("  check_eof %d\n", static_cast<int>(eof));

    return 0;
}
