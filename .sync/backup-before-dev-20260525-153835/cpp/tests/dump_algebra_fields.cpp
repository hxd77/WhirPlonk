// ===========================================================================
// dump_algebra_fields.cpp — Goldilocks 基域及扩域运算 golden test。
//
// 运行: ./dump_algebra_fields > golden_fields_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_fields_rs.txt) golden_fields_cpp.txt
//
// 覆盖 3 个 SECTION (共享同一个 LCG, 保证序列连续):
//   1. base — Fp 基域 (p = 2^64 - 2^32 + 1)
//      测试: 加减取负、乘法、平方、求逆 (费马小定理)、幂 (快速幂)
//      每个 CASE 有 a, b 两个随机输入, 共 3 组
//   2. ext2 — 二次扩域 Fp2 = Fp[X] / (X² - 7)
//      测试: 加减乘、平方、求逆 (共轭法)、Frobenius 自同构
//      Frobenius: (c0+c1·X)^p = c0 - c1·X (取共轭)
//      元素结构: a0 + a1·X, b0 + b1·X
//   3. ext3 — 三次扩域 Fp3 = Fp[X] / (X³ - 2)
//      测试: 同 ext2, 但三次扩域的 Frobenius 更复杂
//      元素结构: a0 + a1·X + a2·X²
//
// 对应 Rust: examples/dump_fields.rs
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/goldilocks_ext2.hpp"
#include "whir/algebra/goldilocks_ext3.hpp"
#include <cstdint>
#include <cstdio>

using whir::algebra::Goldilocks;
using whir::algebra::GoldilocksExt2;
using whir::algebra::GoldilocksExt3;

// ===========================================================================
// LCG — 与 Rust 侧完全一致的伪随机数生成器
// 种子 0xCAFEBABEDEADBEEF 保证 base/ext2/ext3 的序列与 Rust 逐位一致
// ===========================================================================
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

/// 打印基域元素: "  <label> <u64>"
/// as_canonical_u64() 返回规范形式 (C++ 内部存储就是规范值, 不需要 Montgomery 还原)
static void print_base(const char* label, Goldilocks a) {
    std::printf("%s %llu\n", label, (unsigned long long)a.as_canonical_u64());
}

/// 打印二次扩域元素: "  <label> <c0> <c1>"
static void print_ext2(const char* label, GoldilocksExt2 a) {
    std::printf("%s %llu %llu\n", label,
        (unsigned long long)a.c0().as_canonical_u64(),
        (unsigned long long)a.c1().as_canonical_u64());
}

/// 打印三次扩域元素: "  <label> <c0> <c1> <c2>"
static void print_ext3(const char* label, GoldilocksExt3 a) {
    std::printf("%s %llu %llu %llu\n", label,
        (unsigned long long)a.c0().as_canonical_u64(),
        (unsigned long long)a.c1().as_canonical_u64(),
        (unsigned long long)a.c2().as_canonical_u64());
}

int main() {
    Lcg rng(0xCAFEBABEDEADBEEFULL);  // 与 Rust 完全一致

    // ========================================================================
    // SECTION base — Fp = {0, ..., 2^64-2^32} 模运算
    // Goldilocks::from_u64() 自动做模 p 规约 (v >= p 时减 p)
    // ========================================================================
    std::printf("# SECTION base\n");
    for (int i = 0; i < 3; ++i) {
        uint64_t a_raw = rng.next(), b_raw = rng.next();  // 原始 u64 (0~2^64-1)
        auto a = Goldilocks::from_u64(a_raw), b = Goldilocks::from_u64(b_raw);
        std::printf("CASE %d %llu %llu\n", i,
            (unsigned long long)a_raw, (unsigned long long)b_raw);
        print_base("  add", a + b);          // 模加 (自动带溢出处理)
        print_base("  sub", a - b);          // 模减
        print_base("  neg", -a);              // 取负 = p - a
        print_base("  mul", a * b);           // 模乘 (128 位中间结果 + Barrett 约简)
        print_base("  sq",  a.square());      // 平方 a²
        if (!a.is_zero()) {
            print_base("  inv", a.inverse()); // 求逆 a^{p-2} mod p (费马小定理)
        }
        print_base("  pow10", a.pow(10));     // a^10 (快速幂, O(log exp))
    }

    // ========================================================================
    // SECTION ext2 — Fp2 = Fp[X]/(X²-7)
    // 乘法: (a0+a1·X)(b0+b1·X) = (a0b0+7a1b1) + (a0b1+a1b0)·X
    // 求逆: (c0+c1·X)^{-1} = (c0-c1·X)/(c0²-7c1²) (分子分母同乘共轭)
    // ========================================================================
    std::printf("# SECTION ext2\n");
    for (int i = 0; i < 3; ++i) {
        uint64_t a0 = rng.next(), a1 = rng.next(), b0 = rng.next(), b1 = rng.next();
        GoldilocksExt2 a{Goldilocks::from_u64(a0), Goldilocks::from_u64(a1)};
        GoldilocksExt2 b{Goldilocks::from_u64(b0), Goldilocks::from_u64(b1)};
        std::printf("CASE %d %llu %llu %llu %llu\n", i,
            (unsigned long long)a0, (unsigned long long)a1,
            (unsigned long long)b0, (unsigned long long)b1);
        print_ext2("  add", a + b);                   // 分量相加
        print_ext2("  sub", a - b);                   // 分量相减
        print_ext2("  mul", a * b);                   // 交叉乘 + NR·a1b1
        print_ext2("  sq",  a * a);                    // 平方
        if (!(a == GoldilocksExt2::zero())) {
            print_ext2("  inv", a.inverse());          // 共轭/范数 求逆
        }
        print_ext2("  frob1", a.frobenius_map(1));     // Frobenius: (·)^p = 共轭
    }

    // ========================================================================
    // SECTION ext3 — Fp3 = Fp[X]/(X³-2)
    // 乘法用 Karatsuba 风格的分治, 求逆用扩展欧几里得
    // ========================================================================
    std::printf("# SECTION ext3\n");
    for (int i = 0; i < 3; ++i) {
        uint64_t a0 = rng.next(), a1 = rng.next(), a2 = rng.next();
        uint64_t b0 = rng.next(), b1 = rng.next(), b2 = rng.next();
        GoldilocksExt3 a{Goldilocks::from_u64(a0), Goldilocks::from_u64(a1), Goldilocks::from_u64(a2)};
        GoldilocksExt3 b{Goldilocks::from_u64(b0), Goldilocks::from_u64(b1), Goldilocks::from_u64(b2)};
        std::printf("CASE %d %llu %llu %llu %llu %llu %llu\n", i,
            (unsigned long long)a0, (unsigned long long)a1, (unsigned long long)a2,
            (unsigned long long)b0, (unsigned long long)b1, (unsigned long long)b2);
        print_ext3("  add", a + b);
        print_ext3("  sub", a - b);
        print_ext3("  mul", a * b);
        print_ext3("  sq",  a * a);
        if (!(a == GoldilocksExt3::zero())) {
            print_ext3("  inv", a.inverse());
        }
        print_ext3("  frob1", a.frobenius_map(1));
    }
    return 0;
}
