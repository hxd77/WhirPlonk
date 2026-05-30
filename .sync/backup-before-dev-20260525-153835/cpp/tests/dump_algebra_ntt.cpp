// ===========================================================================
// dump_algebra_ntt.cpp — NTT / Wavelet / Transpose golden test。
//
// 运行: ./dump_algebra_ntt > golden_ntt_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_ntt_rs.txt) golden_ntt_cpp.txt
//
// 覆盖 3 个 SECTION, 每个用独立 LCG 种子:
//   1. ntt       — 数论变换 (Number Theoretic Transform)
//                  把多项式系数转为求值点表示 (用于 RS 编码)
//                  Goldilocks 支持最大 2^32 个点
//   2. wavelet   — 小波变换
//                  将 NTT 输出重组为小波基, 用于 WHIR 递归折叠
//   3. transpose — 矩阵转置
//                  用于 NTT 六步法 (Cooley-Tukey 算法的矩阵分解步骤)
//                  这里测试 8×4 u64 矩阵 (非域元素)
//
// 对应 Rust: examples/dump_ntt.rs
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/transpose.hpp"
#include "whir/algebra/ntt/wavelet.hpp"
#include <cstdint>
#include <cstdio>
#include <vector>

using whir::algebra::Goldilocks;

// LCG — 与 Rust 侧完全一致的伪随机数生成器
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

static void print_base(const char* label, Goldilocks a) {
    std::printf("%s %llu\n", label, (unsigned long long)a.as_canonical_u64());
}

int main() {
    auto dump_base_vec = [](const char* label, const std::vector<Goldilocks>& v) {
        std::printf("  %s %zu\n", label, v.size());
        for (const auto& x : v) std::printf("     %llu\n", (unsigned long long)x.as_canonical_u64());
    };

    // ========================================================================
    // SECTION ntt — 正向 NTT (seed: 0x4444...)
    //
    // engine.ntt(span) 原地将系数向量转为求值点表示。
    // 测试 4/8/16/64 四个不同大小。
    //
    // goldilocks_engine() 返回预配置的 NttEngine<Goldilocks> 单例,
    // order=2^32, 因此支持所有 ≤ 2^32 的 2 的幂次大小。
    // ========================================================================
    std::printf("# SECTION ntt\n");
    {   Lcg rng(0x4444444444444444ULL);
        auto& engine = whir::algebra::ntt::goldilocks_engine();
        int ci = 0;
        for (std::size_t n : {std::size_t{4}, std::size_t{8}, std::size_t{16}, std::size_t{64}}) {
            std::vector<Goldilocks> vals;
            for (std::size_t i = 0; i < n; ++i) vals.push_back(Goldilocks::from_u64(rng.next()));
            engine.ntt(std::span<Goldilocks>{vals});  // 原地 NTT
            std::printf("CASE %d ntt n=%zu\n", ci++, n); dump_base_vec("out", vals);
        }
    }

    // ========================================================================
    // SECTION wavelet — 小波变换 (seed: 0x5555...)
    //
    // wavelet_transform 把 NTT 求值结果重排为小波基排列,
    // 这种排列更利于 WHIR 的递归折叠操作。
    // 测试 8/64 两个大小。
    // ========================================================================
    std::printf("# SECTION wavelet\n");
    {   Lcg rng(0x5555555555555555ULL);
        int ci = 0;
        for (std::size_t n : {std::size_t{8}, std::size_t{64}}) {
            std::vector<Goldilocks> vals;
            for (std::size_t i = 0; i < n; ++i) vals.push_back(Goldilocks::from_u64(rng.next()));
            whir::algebra::ntt::wavelet_transform<Goldilocks>(std::span<Goldilocks>{vals});
            std::printf("CASE %d wavelet n=%zu\n", ci++, n); dump_base_vec("out", vals);
        }
    }

    // ========================================================================
    // SECTION transpose — 矩阵转置 (seed: 0x6666...)
    //
    // 这里转置 8×4 的 u64 矩阵。
    // 用于 NTT 六步法中, 把列方向的数据重新组织为行方向。
    // ========================================================================
    std::printf("# SECTION transpose\n");
    {   Lcg rng(0x6666666666666666ULL);
        const std::size_t R = 8, C = 4;  // 8 行 × 4 列
        std::vector<uint64_t> m;
        for (std::size_t i = 0; i < R * C; ++i) m.push_back(rng.next());
        whir::algebra::ntt::transpose<uint64_t>(std::span<uint64_t>{m}, R, C);
        std::printf("CASE 0 transpose 8x4\n");
        for (auto v : m) std::printf("  %llu\n", (unsigned long long)v);
    }
    return 0;
}
