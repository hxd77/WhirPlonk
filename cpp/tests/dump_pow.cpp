// ===========================================================================
// dump_pow.cpp — Proof of Work golden test。
//
// 运行: ./dump_pow > golden_pow_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_pow_rs.txt) golden_pow_cpp.txt
//
// 测试 PoW nonce 查找:
//   给定 challenge (32 字节) + threshold (u64),
//   找最小的 nonce 使得:
//     hash(challenge || nonce_le || zeros_24) 的前 8 字节 (LE u64) ≤ threshold
//
// 输入布局 (64 字节):
//   [0..32):  challenge (32 B)
//   [32..40): nonce (8 B, little-endian)
//   [40..64): zeros  (24 B, 用于补齐 SHA-256/BLAKE3 块大小)
//
// 2 组测试用例:
//   - BLAKE3, threshold = 2^60 (4 bits 难度), challenge = [0xAA; 32]
//   - SHA2,   threshold = 2^60,                challenge = [0x55; 32]
//
// 对应 Rust: examples/dump_pow.rs
// ===========================================================================

//测试 Proof of Work (PoW) 的 nonce 查找是否和 Rust 端结果一致。
//具体来说：
//  1. 输入：一个固定的 32 字节 challenge + 一个阈值 threshold
//  2. 查找：从 nonce=0 开始递增，找最小的 nonce 使得 hash(challenge || nonce_le || zeros_24) 的前 8 字节（LE u64）≤ threshold
//  3. 输出：找到的 nonce 值 + 该 nonce 对应的完整哈希

#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/proof_of_work.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    auto dump_hash = [](const char* label, const whir::hash::Hash& h) {
        std::printf("  %s ", label);
        for (auto byte : h) std::printf("%02x", static_cast<unsigned>(byte));
        std::printf("\n");
    };
    using whir::hash::Hash;

    whir::hash::Blake3 b3e;
    whir::hash::Sha2 s2e;

    // 测试用例: (标签, 引擎, 阈值, challenge字节)
    struct Case { const char* label; const whir::hash::HashEngine* e; uint64_t thr; uint8_t cb; };
    const std::vector<Case> cases = {
        {"blake3-thr60bits", &b3e, uint64_t{1} << 60, 0xAA},
        {"sha2-thr60bits",   &s2e, uint64_t{1} << 60, 0x55}, 
    };
    //threhold=0x00000000FFFFFFFF

    std::printf("# SECTION pow\n");
    for (std::size_t ci = 0; ci < cases.size(); ++ci) {
        const auto& c = cases[ci];

        // 构造 challenge (32 字节全相同)
        std::array<std::uint8_t, 32> ch{};
        ch.fill(c.cb); //用cb填充32字节 

        // 批处理: 每批检查 batch 个 nonce (提高吞吐)
        std::size_t batch = std::max<std::size_t>(c.e->preferred_batch_size(), 1); //确定一次处理最少1个数据
        std::vector<std::uint8_t> inputs(64 * batch, 0); //用0填充64个数据
        for (std::size_t i = 0; i < batch; ++i)
            std::memcpy(&inputs[64 * i], ch.data(), 32);  // 复制 challenge的32字节放到input中

        //input:[AA AA ... AA (32个)] [00 00 ... 00 (32个)]

        std::vector<Hash> outs(batch);
        uint64_t fn = 0;       // 找到的 nonce
        bool found = false;

        //前面已经填好了32字节，现在要在后面32字节的8字节中填入Nonce(一个不断累加的数字)
        // 从 nonce=0 开始, 逐批搜索 知道found=true
        for (uint64_t base = 0; !found; base += batch) {
            // 写入本批的 nonce 值 (LE)
            for (std::size_t i = 0; i < batch; ++i) {
                uint64_t n = base + (uint64_t)i;
                for (int b = 0; b < 8; ++b) //把n这个数字从低位到高位依次取出
                    inputs[64 * i + 32 + b] = (uint8_t)((n >> (8 * b)) & 0xFFu);
                    //b=0获取最低位,填入inputs[32+0]
                    //b=1获取第二个字节,填入input[32+1]
                    //n=base+0=0
                    //inputs:[32字节AA] [00 00 00 00 00 00 00 00] [剩余24字节00]
            }
            // 批量哈希
            c.e->hash_many(64, //输出64个字节
                std::span<const std::uint8_t>{inputs.data(), inputs.size()},
                std::span<Hash>{outs.data(), outs.size()}); //调用hash_many生成了一个hash值,假设:[DE AD BE EF 12 34 56 78 ...]

            // 检查每个 nonce: 哈希前 8 字节 LE → u64, 与 threshold 比较
            for (std::size_t i = 0; i < batch; ++i) { 
                uint64_t v = 0;
                for (int b = 7; b >= 0; --b) //大端序读取方式
                    v = (v << 8) | (uint64_t)outs[i][b];  // 大端到小端,拼接v = 0x78563412EFBEADDE
                if (v <= c.thr) { //大于c.thr
                    fn = base + (uint64_t)i;
                    found = true;
                    break;
                }
            }
            //base+=batch=1
            //b=0x01,inputs :[32字节AA] [01 00 00 00 00 00 00 00] [剩余24字节00]
            //调用hash_many,假设输出[FF FF FF FF 00 00 00 00 ...]
            //最终拼接v = 0x00000000FFFFFFFF
            //v<=c.thr, fn=1
        }

        // 再哈希一次得到正式输出 (用于对拍验证一致性)
        std::array<std::uint8_t, 64> si{};
        std::memcpy(si.data(), ch.data(), 32); //复制32字节到si中
        for (int b = 0; b < 8; ++b)
            si[32 + b] = (uint8_t)((fn >> (8 * b)) & 0xFFu); //把fn按小端序填入si的32-39字节,重构原始数据
        Hash so{};
        c.e->hash_many(64,
            std::span<const std::uint8_t>{si.data(), si.size()},
            std::span<Hash>{&so, 1});  //1个哈希

        std::printf("CASE %zu %s threshold=%llu\n  nonce %llu\n",
            ci, c.label, (unsigned long long)c.thr, (unsigned long long)fn);
        dump_hash("hash", so);
    }
    return 0;
}
