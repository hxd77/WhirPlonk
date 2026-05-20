#pragma once

// ============================================================================
// geometric_challenge.hpp — 从 transcript 生成几何序列挑战
//
// 从 Fiat-Shamir transcript 挤压一个随机域元素 x，然后生成几何（幂）序列:
//   count == 0 -> 空
//   count == 1 -> [1]              （无需随机性）
//   count >= 2 -> [1, x, x^2, ..., x^{count-1}]
//
// 在 WHIR 中的用途:
//   这是标准的"随机线性组合"（RLC）构造。给定 count 个待组合对象，
//   使用 [1, x, x^2, ...] 作为系数。只需一次 transcript 挤压，
//   而非 count 次独立抽取。
//   性质:
//     - 首个系数固定为 1（复用首个对象作为累加器）
//     - 系数非独立，但安全性保持
//
// 用法:
//   auto coeffs = geometric_challenge<F>(transcript, num_constraints);
//   // coeffs[0] = 1, coeffs[1] = x, coeffs[2] = x^2, ...
//
// C++ 代数: algebra/utilities.hpp (geometric_sequence)
// 对应 Rust 文件: src/protocols/geometric_challenge.rs
// ============================================================================

#include "../algebra/utilities.hpp"
#include "../transcript/transcript.hpp"

#include <vector>

namespace whir::protocols {

/// 从 transcript 挤压随机元素 x，返回几何序列 [1, x, x^2, ..., x^{count-1}]。
///
/// @tparam F          域元素类型
/// @tparam Transcript 必须支持 verifier_message<F>()
template <typename F, typename Transcript>
std::vector<F> geometric_challenge(Transcript& transcript, std::size_t count) {
    if (count == 0) return {};
    if (count == 1) return {F::one()};
    F x = transcript.template verifier_message<F>();
    return ::whir::algebra::geometric_sequence<F>(x, count);
}

} // namespace whir::protocols
