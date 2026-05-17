// ===========================================================================
// dump_matrix_commit.cpp — 矩阵承诺 golden test。
//
// 运行: ./dump_matrix_commit > golden_mcommit_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_mcommit_rs.txt) golden_mcommit_cpp.txt
//
// 测试 commit_leaves(): 对矩阵每一行做域元素 LE 编码 + 哈希, 得到叶子哈希列表。
// 这是 Merkle 树构建的前置步骤 — 把域元素矩阵转成字节哈希叶子。
//
// 5 组测试用例 (不同域 × 不同引擎 × 不同尺寸):
//   CASE 0: Goldilocks    × BLAKE3, 4×8  (msg=8*8=64,  满足 BLAKE3 64 倍数要求)
//   CASE 1: GoldilocksExt2 × BLAKE3, 2×8  (msg=16*8=128)
//   CASE 2: GoldilocksExt3 × SHA2,   3×5  (msg=24*5=120, SHA2 支持任意)
//   CASE 3: Goldilocks    × SHA2,   2×4  (msg=8*4=32)
//   CASE 4: Goldilocks    × COPY,   3×4  (msg=32,  用于测试 ≤32 边界)
//
// encoded_size<T>: 单元素 LE 编码字节数
//   Goldilocks     = 8  (u64 LE)
//   GoldilocksExt2 = 16 (c0 LE + c1 LE)
//   GoldilocksExt3 = 24 (c0 LE + c1 LE + c2 LE)
//
// 注意: C++ 函数实参求值顺序未定义, Ext2/Ext3 构造时必须用
//       具名局部变量强制 LTR 求值, 否则与 Rust 字节级对拍会挂。
//
// 对应 Rust: examples/dump_matrix_commit.rs
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/goldilocks_ext2.hpp"
#include "whir/algebra/goldilocks_ext3.hpp"
#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/copy_engine.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/matrix_commit.hpp"
#include <cstdint>
#include <cstdio>
#include <vector>

using whir::algebra::Goldilocks;
using whir::algebra::GoldilocksExt2;
using whir::algebra::GoldilocksExt3;

// LCG — 与 Rust 侧完全一致
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

int main() {
    auto dump_hash = [](const char* label, const whir::hash::Hash& h) {
        std::printf("  %s ", label);
        for (auto byte : h) std::printf("%02x", static_cast<unsigned>(byte));
        std::printf("\n");
    };

    namespace mc = whir::protocols::matrix_commit;
    Lcg rng(0xBBBBBBBBBBBBBBBBULL);

    // 引擎实例
    whir::hash::Copy cp;
    whir::hash::Blake3 b3;
    whir::hash::Sha2 s2;

    std::printf("# SECTION matrix_commit\n");

    // ---- CASE 0: Goldilocks × Blake3, 4 行 × 8 列 ----
    // msg_size = 8 * 8 = 64, 满足 BLAKE3 64 倍数要求
    {   const std::size_t nr = 4, nc = 8, tot = nr * nc;
        std::vector<Goldilocks> mat; mat.reserve(tot);
        for (std::size_t i = 0; i < tot; ++i)
            mat.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<whir::hash::Hash> leaves(nr);
        // commit_leaves: 编码矩阵 + 行哈希, 输出 nr 个叶子哈希
        mc::commit_leaves<Goldilocks>(b3,
            std::span<const Goldilocks>{mat}, nc,
            std::span<whir::hash::Hash>{leaves});
        std::size_t ms = mc::encoded_size<Goldilocks>() * nc; //每行编码字节大小
        std::printf("CASE 0 field64-blake3 rows=%zu cols=%zu msg_size=%zu\n", nr, nc, ms);
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            char b[16]; std::snprintf(b, 16, "leaf%zu", i); dump_hash(b, leaves[i]);
        }
    }

    // ---- CASE 1: GoldilocksExt2 × Blake3, 2 行 × 8 列 ----
    // msg_size = 16 * 8 = 128
    // 具名局部变量强制 LTR 求值顺序 (c0 在 c1 之前)
    {   const std::size_t nr = 2, nc = 8, tot = nr * nc;
        std::vector<GoldilocksExt2> mat; mat.reserve(tot);
        for (std::size_t i = 0; i < tot; ++i) {
            auto c0 = Goldilocks::from_u64(rng.next());
            auto c1 = Goldilocks::from_u64(rng.next());
            mat.emplace_back(c0, c1);
        }
        std::vector<whir::hash::Hash> leaves(nr);
        mc::commit_leaves<GoldilocksExt2>(b3,
            std::span<const GoldilocksExt2>{mat}, nc,
            std::span<whir::hash::Hash>{leaves});
        std::size_t ms = mc::encoded_size<GoldilocksExt2>() * nc;
        std::printf("CASE 1 field64_2-blake3 rows=%zu cols=%zu msg_size=%zu\n", nr, nc, ms);
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            char b[16]; std::snprintf(b, 16, "leaf%zu", i); dump_hash(b, leaves[i]);
        }
    }

    // ---- CASE 2: GoldilocksExt3 × Sha2, 3 行 × 5 列 ----
    // msg_size = 24 * 5 = 120, SHA-256 支持任意大小
    {   const std::size_t nr = 3, nc = 5, tot = nr * nc;
        std::vector<GoldilocksExt3> mat; mat.reserve(tot);
        for (std::size_t i = 0; i < tot; ++i) {
            auto c0 = Goldilocks::from_u64(rng.next());
            auto c1 = Goldilocks::from_u64(rng.next());
            auto c2 = Goldilocks::from_u64(rng.next());
            mat.emplace_back(c0, c1, c2);
        }
        std::vector<whir::hash::Hash> leaves(nr);
        mc::commit_leaves<GoldilocksExt3>(s2,
            std::span<const GoldilocksExt3>{mat}, nc,
            std::span<whir::hash::Hash>{leaves});
        std::size_t ms = mc::encoded_size<GoldilocksExt3>() * nc;
        std::printf("CASE 2 field64_3-sha2 rows=%zu cols=%zu msg_size=%zu\n", nr, nc, ms);
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            char b[16]; std::snprintf(b, 16, "leaf%zu", i); dump_hash(b, leaves[i]);
        }
    }

    // ---- CASE 3: Goldilocks × Sha2, 2 行 × 4 列 ----
    // msg_size = 8 * 4 = 32
    {   const std::size_t nr = 2, nc = 4, tot = nr * nc;
        std::vector<Goldilocks> mat; mat.reserve(tot);
        for (std::size_t i = 0; i < tot; ++i)
            mat.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<whir::hash::Hash> leaves(nr);
        mc::commit_leaves<Goldilocks>(s2,
            std::span<const Goldilocks>{mat}, nc,
            std::span<whir::hash::Hash>{leaves});
        std::size_t ms = mc::encoded_size<Goldilocks>() * nc;
        std::printf("CASE 3 field64-sha2 rows=%zu cols=%zu msg_size=%zu\n", nr, nc, ms);
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            char b[16]; std::snprintf(b, 16, "leaf%zu", i); dump_hash(b, leaves[i]);
        }
    }

    // ---- CASE 4: Goldilocks × Copy, 3 行 × 4 列 ----
    // msg_size = 32, Copy 引擎支持 ≤ 32 (直接复制, 不哈希)
    {   const std::size_t nr = 3, nc = 4, tot = nr * nc;
        std::vector<Goldilocks> mat; mat.reserve(tot);
        for (std::size_t i = 0; i < tot; ++i)
            mat.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<whir::hash::Hash> leaves(nr);
        mc::commit_leaves<Goldilocks>(cp,
            std::span<const Goldilocks>{mat}, nc,
            std::span<whir::hash::Hash>{leaves});
        std::size_t ms = mc::encoded_size<Goldilocks>() * nc;
        std::printf("CASE 4 field64-copy rows=%zu cols=%zu msg_size=%zu\n", nr, nc, ms);
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            char b[16]; std::snprintf(b, 16, "leaf%zu", i); dump_hash(b, leaves[i]);
        }
    }
    return 0;
}
