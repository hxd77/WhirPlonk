// ===========================================================================
// dump_hash.cpp — 哈希引擎 golden test。
//
// 运行: ./dump_hash > golden_hash_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_hash_rs.txt) golden_hash_cpp.txt
//
// 测试 3 种哈希引擎的 hash_many 输出 (seed: 0xAAAA...):
//   - COPY   (恒等映射, size ≤ 32)
//   - BLAKE3 (高性能, size 必须是 64 的倍数且 ≤ 1024)
//   - SHA2   (SHA-256, 任意 size)
//
// hash_many(size, input, output):
//   input 是 output.size() 段连续消息 (每段 size 字节) 拼成的扁平 buffer
//   对每段独立哈希, 结果写入 output[i]
//
// 对应 Rust: examples/dump_hash.rs
// ===========================================================================

#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/copy_engine.hpp"
#include "whir/hash/sha2_engine.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// LCG — 与 Rust 侧完全一致, 用于生成确定性输入数据
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

int main() {
    Lcg rng(0xAAAAAAAAAAAAAAAAULL);

    // 打印哈希值为 64 字符十六进制字符串
    auto print_hash = [](const char* label, const whir::hash::Hash& h) {
        std::printf("  %s ", label);
        for (auto byte : h) std::printf("%02x", static_cast<unsigned>(byte));
        std::printf("\n");
    };

    // 从 LCG 取 n 字节确定性输入 (每次取 u64, 按 LE 拆成 8 字节)
    auto make_bytes = [&](std::size_t n) {
        std::vector<std::uint8_t> v; v.reserve(n);
        while (v.size() < n) {
            std::uint64_t w = rng.next();
            for (int i = 0; i < 8 && v.size() < n; ++i) {
                v.push_back((uint8_t)(w & 0xFFu));
                w >>= 8;
            }
        }
        return v;
    };

    // 通用测试闭包: 用指定引擎, 生成 size*count 字节随机输入, 批量哈希
    auto run = [&](int ci, const whir::hash::HashEngine& eng,
                   const char* label, std::size_t sz, std::size_t cnt) {
        auto input = make_bytes(sz * cnt);
        std::vector<whir::hash::Hash> out(cnt);
        eng.hash_many(sz,
            std::span<const std::uint8_t>{input.data(), input.size()},
            std::span<whir::hash::Hash>{out.data(), out.size()});
        std::printf("CASE %d %s size=%zu count=%zu\n", ci, label, sz, cnt);

        for (std::size_t i = 0; i < out.size(); ++i) {
            char b[8]; std::snprintf(b, 8, "h%zu", i); print_hash(b, out[i]);
        }
    };

    // 创建引擎实例
    whir::hash::Copy copy_eng;
    whir::hash::Blake3 blake3_eng;
    whir::hash::Sha2 sha2_eng;

    std::printf("# SECTION hash\n");

    // ---- COPY: 恒等映射, size 必须 ≤ 32 ----
    run(0, copy_eng,   "copy",   0,    2);   // 0 字节 → 全零哈希
    run(1, copy_eng,   "copy",   16,   2);   // 16 字节 → 直接复制
    run(2, copy_eng,   "copy",   32,   3);   // 32 字节 → 填满

    // ---- BLAKE3: size 必须是 64 倍数且 ≤ 1024 ----
    run(3, blake3_eng, "blake3", 64,   1);   // 1 个 64B 消息
    run(4, blake3_eng, "blake3", 64,   4);   // 4 个 64B 消息 (批处理)
    run(5, blake3_eng, "blake3", 128,  2);   // 2 个 128B 消息
    run(6, blake3_eng, "blake3", 256,  1);   // 1 个 256B 消息
    run(7, blake3_eng, "blake3", 1024, 1);   // 1 个 1024B (CHUNK_LEN 上限)

    // ---- SHA2 (SHA-256): 任意 size ----
    run(8, sha2_eng,   "sha2",   0,    1);   // 空消息: SHA-256("")
    run(9, sha2_eng,   "sha2",   31,   1);   // 奇数长度
    run(10, sha2_eng,  "sha2",   32,   3);   // 恰好一个 SHA-256 块
    run(11, sha2_eng,  "sha2",   64,   2);   // 两个块
    run(12, sha2_eng,  "sha2",   100,  2);   // 非对齐长度
    return 0;
}
