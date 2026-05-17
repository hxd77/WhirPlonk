#pragma once

// =============================================================================
// cooley_tukey_goldilocks.hpp — Goldilocks 域系列的 NTT 引擎单例。
//
// 为 Goldilocks / GoldilocksExt2 / GoldilocksExt3 提供全局单例 NttEngine,
// 避免每次使用时重新构造引擎 (包括单位根预计算和根表懒惰初始化)。
//
// 与 Rust 的 ENGINE_CACHE 大致对应, 但 C++ 端为头文件内 static 局部变量,
// 单线程使用无需锁。
//
// 提供:
//   goldilocks_engine()        — 返回 NttEngine<Goldilocks> 单例引用
//   goldilocks_ext2_engine()   — 返回 NttEngine<GoldilocksExt2> 单例引用
//   goldilocks_ext3_engine()   — 返回 NttEngine<GoldilocksExt3> 单例引用
//   generator<F>(size)         — 返回 size 阶本原单位根 (若存在)
// =============================================================================

#include "../goldilocks.hpp"
#include "../goldilocks_ext2.hpp"
#include "../goldilocks_ext3.hpp"
#include "cooley_tukey.hpp"

namespace whir::algebra::ntt {

// ---------------------------------------------------------------------------
// goldilocks_engine() — 获取 Goldilocks 基域的 NTT 引擎单例。
//
// 引擎参数:
//   本原单位根: Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY)
//              = 2^32 阶本原单位根 (Goldilocks 域的最大 2-adic 阶)
//   order: 2^TWO_ADICITY = 2^32
//
// 输出: NttEngine<Goldilocks>& 静态单例引用
// 注意: 首次调用时构造 (包含根表懒惰初始化), 后续调用 O(1)。
// ---------------------------------------------------------------------------
inline NttEngine<Goldilocks>& goldilocks_engine() {
    static NttEngine<Goldilocks> eng = NttEngine<Goldilocks>::from_two_adic(
        Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY),
        Goldilocks::TWO_ADICITY);
    return eng;
}

// ---------------------------------------------------------------------------
// goldilocks_ext2_engine() — 获取 Goldilocks 二次扩域的 NTT 引擎单例。
//
// Ext2 没有独立的更高 two-adicity 的根; 此处复用 Goldilocks 子域的 2^32 阶根,
// 通过 from_base() 嵌入到扩域中。
//
// 输出: NttEngine<GoldilocksExt2>& 静态单例引用
// ---------------------------------------------------------------------------
inline NttEngine<GoldilocksExt2>& goldilocks_ext2_engine() {
    static NttEngine<GoldilocksExt2> eng = NttEngine<GoldilocksExt2>::from_two_adic(
        GoldilocksExt2::from_base(Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY)),
        Goldilocks::TWO_ADICITY);
    return eng;
}

// ---------------------------------------------------------------------------
// goldilocks_ext3_engine() — 获取 Goldilocks 三次扩域的 NTT 引擎单例。
// 与 Ext2 相同, 复用基域的 2^32 阶根嵌入。
// 输出: NttEngine<GoldilocksExt3>& 静态单例引用
// ---------------------------------------------------------------------------
inline NttEngine<GoldilocksExt3>& goldilocks_ext3_engine() {
    static NttEngine<GoldilocksExt3> eng = NttEngine<GoldilocksExt3>::from_two_adic(
        GoldilocksExt3::from_base(Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY)),
        Goldilocks::TWO_ADICITY);
    return eng;
}

// ---------------------------------------------------------------------------
// generator<F>(size) — 对标 Rust 的 ntt::generator<F>(size) -> Option<F>。
//
// 输入: size — 需要的单位根阶数
// 输出: std::optional<F>
//       - 若当前引擎的 order 能被 size 整除, 返回对应的 size 阶本原单位根
//       - 否则返回 std::nullopt
//
// 内部实现: 通过对应域的引擎单例调用 checked_root(size)。
//
// 模板特化:
//   F=Goldilocks      → goldilocks_engine().checked_root(size)
//   F=GoldilocksExt2  → goldilocks_ext2_engine().checked_root(size)
//   F=GoldilocksExt3  → goldilocks_ext3_engine().checked_root(size)
// ---------------------------------------------------------------------------

template <typename F>
std::optional<F> generator(std::size_t size);

template <>
inline std::optional<Goldilocks> generator<Goldilocks>(std::size_t size) {
    return goldilocks_engine().checked_root(size);
}

template <>
inline std::optional<GoldilocksExt2> generator<GoldilocksExt2>(std::size_t size) {
    return goldilocks_ext2_engine().checked_root(size);
}

template <>
inline std::optional<GoldilocksExt3> generator<GoldilocksExt3>(std::size_t size) {
    return goldilocks_ext3_engine().checked_root(size);
}

} // namespace whir::algebra::ntt
