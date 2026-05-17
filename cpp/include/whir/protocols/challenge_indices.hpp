#pragma once

// 对应 WHIR 中的 src/protocols/challenge_indices.rs 的纯函数核心。
// transcript 包装 (从 verifier_message 取 entropy 字节) 推迟到 Phase 5b。
//
// 提供:
//   indices_from_entropy(entropy, num_leaves, count, deduplicate) -> vector<size_t>
//
// 算法 (与 Rust 端 challenge_indices() 内部完全一致):
//   - count == 0          → 返空
//   - num_leaves == 1     → dedup ? [0] : count 个 0
//   - 否则 size_bytes = ceil(log2(num_leaves)/8), entropy 长度 = count*size_bytes
//   - 每段 size_bytes 字节按 big-endian 解码再 mod num_leaves
//   - dedup → sort + unique
//
// 注意: num_leaves 必须是 2 的幂 (Rust 端 assert), 不是会触发断言。

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "../transcript/transcript.hpp"

namespace whir::protocols::challenge_indices {

//判断一个无符号整数是否是2的幂
inline bool is_power_of_two(std::size_t n) noexcept {
    return n != 0 && (n & (n - 1)) == 0; //1000&0111=0
}

//计算一个以2的幂为底数的底数
//ceil(log2(n)) for n >= 1, n 是 2 的幂时即 trailing-zeros count。
inline std::size_t log2_pow2(std::size_t n) noexcept {
    assert(n >= 1 && (n & (n - 1)) == 0);
    std::size_t k = 0;
    while ((std::size_t{1} << k) < n) ++k;
    return k;
}

//将一段随机字节流转换成一组数值索引列表
inline std::vector<std::size_t> indices_from_entropy(
    std::span<const std::uint8_t> entropy,
    std::size_t num_leaves, //叶子节点个数
    std::size_t count, //生成索引
    bool deduplicate) //布尔开关,是否进行去重并进行排序
{
    if (count == 0) return {};
    assert(is_power_of_two(num_leaves) && "num_leaves must be a power of two"); //必须是2的幂次
    if (num_leaves == 1) {
        if (deduplicate) return {0}; //[0]
        return std::vector<std::size_t>(count, 0); //[0,0,0...]
    }

    //计算每个索引需要多少个字节
    //假如num_leaves=1024=2^10,需要10个bit,所以size_bytes=17/8=2需要2个字节
    const std::size_t size_bytes = (log2_pow2(num_leaves) + 7) / 8;
    assert(entropy.size() == count * size_bytes && "entropy length mismatch");

    std::vector<std::size_t> indices;
    indices.reserve(count); 
    //从字节流中拼装数字并生成索引
    for (std::size_t i = 0; i < count; ++i) {
        std::size_t acc = 0;
        for (std::size_t b = 0; b < size_bytes; ++b) {
            //每次循环从entropy中读取size_bytes个字节,然后通过大端序拼接成一个大整数
            acc = (acc << 8) | static_cast<std::size_t>(entropy[i * size_bytes + b]);
        }
        indices.push_back(acc % num_leaves); //取余数使随机数到叶子节点总数范围内
    }

    if (deduplicate) { //如果去重
        std::sort(indices.begin(), indices.end()); //从小到大排好
        indices.erase(std::unique(indices.begin(), indices.end()), indices.end());//重复元素移到末尾然后删除
    }
    return indices;
}

// transcript 包装: 从 transcript 挤出 entropy 字节, 然后调用 indices_from_entropy。
//通过Transcript自动生成一段随机字节,然后利用这些字节生成一组"挑战索引"
template <typename Transcript>
std::vector<std::size_t> challenge_indices(
    Transcript& transcript,
    std::size_t num_leaves,
    std::size_t count, //多少个挑战索引
    bool deduplicate)
{
    if (count == 0) return {};
    assert(is_power_of_two(num_leaves));
    if (num_leaves == 1) {
        if (deduplicate) return {0};
        return std::vector<std::size_t>(count, 0);
    }
    //计算每个索引需要多少个字节
    const std::size_t size_bytes = (log2_pow2(num_leaves) + 7) / 8;
    std::size_t total_bytes = count * size_bytes; 
    std::vector<std::uint8_t> entropy(total_bytes); //开辟一个total_bytes大的空数组entropy
    // 逐字节挤出 entropy
    for (auto& b : entropy)
        //从transcript从抽取uint8_t赋值给b
        b = transcript.template verifier_message<std::uint8_t>(); //template表示<>是一个模板而不是大于小于号
    return indices_from_entropy(entropy, num_leaves, count, deduplicate);//最后生成一组挑战值索引
}

} // namespace whir::protocols::challenge_indices
