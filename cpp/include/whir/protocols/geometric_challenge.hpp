#pragma once

// ===========================================================================
// geometric_challenge.hpp — 从 transcript 产生几何序列挑战值
// 对应 WHIR 中的 src/protocols/geometric_challenge.rs。
//
// 从 transcript 挤出一个随机域元素 x, 然后生成几何序列:
//   count == 0 → 空
//   count == 1 → [1]           (不需要随机性)
//   count >= 2 → [1, x, x², ..., x^{count-1}]
//
// 在 WHIR 中的用途:
//   geometric_challenge 是 "随机线性组合 (RLC)" 的标准构造。
//   给定 count 个待组合的对象, 用 [1, x, x², ...] 作为系数,
//   只需要 transcript 挤出一个随机数 x, 而不是 count 个独立随机数。
//   这保证了:
//     1. 第一个系数固定为 1 (可以回收第一个对象作为累加器, 节省一次乘法)
//     2. 系数之间不是独立随机的, 但仍然满足 soundness 要求
//
// 用法:
//   auto coeffs = geometric_challenge<F>(transcript, num_constraints);
//   // coeffs[0] = 1, coeffs[1] = x, coeffs[2] = x², ...
//
// 对应 C++ algebra: algebra/utilities.hpp (geometric_sequence)
// ===========================================================================

#include "../algebra/utilities.hpp"
#include "../transcript/transcript.hpp"

#include <vector>

namespace whir::protocols {

/// 从 transcript 挤出随机数 x, 生成几何序列 [1, x, x², ..., x^{count-1}]。
/// Transcript 必须支持 verifier_message<F>()。
template <typename F, typename Transcript> //双参数模板
std::vector<F> geometric_challenge(Transcript& transcript, std::size_t count) {
    if (count == 0) return {};                      // 无约束 → 空
    if (count == 1) return {F::one()};               // 单约束 → 系数固定为 1
    F x = transcript.template verifier_message<F>(); // 只消耗一次随机性
    return ::whir::algebra::geometric_sequence<F>(x, count);  // [1, x, x², ...]
}

} // namespace whir::protocols
