#pragma once

// ============================================================================
// cooley_tukey_goldilocks.hpp — Goldilocks 域单例 NTT 引擎
//
// 为 Goldilocks、GoldilocksExt2、GoldilocksExt3 提供全局单例 NttEngine 实例。
// 每个引擎通过 static 局部变量惰性构造（无锁，仅限单线程使用）。
//
// 对应 Rust 中的 ENGINE_CACHE，针对 C++ 做了简化。
//
// 对应 Rust 源文件：src/algebra/ntt/cooley_tukey.rs（引擎缓存层）
// ============================================================================

//为Goldilocks相关有限域创建全局NTT引擎,并提供一个统一的generator<F>接口,用来获取指定阶数的NTT单位根
#include "../goldilocks.hpp"
#include "../goldilocks_ext2.hpp"
#include "../goldilocks_ext3.hpp"
#include "cooley_tukey.hpp"

namespace whir::algebra::ntt {

// 返回 Goldilocks 域的单例 NttEngine。
// 使用 2^32 阶本原单位根构造（Goldilocks::TWO_ADICITY）。
inline NttEngine<Goldilocks>& goldilocks_engine() {
    static NttEngine<Goldilocks> eng = NttEngine<Goldilocks>::from_two_adic(
        Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY),
        Goldilocks::TWO_ADICITY);
    return eng;
}

// 返回 GoldilocksExt2 域的单例 NttEngine。
// 通过 from_base() 将基域 2^32 阶单位根嵌入扩域。
inline NttEngine<GoldilocksExt2>& goldilocks_ext2_engine() {
    static NttEngine<GoldilocksExt2> eng = NttEngine<GoldilocksExt2>::from_two_adic(
        GoldilocksExt2::from_base(Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY)),
        Goldilocks::TWO_ADICITY);
    return eng;
}

// 返回 GoldilocksExt3 域的单例 NttEngine。
// 通过 from_base() 将基域 2^32 阶单位根嵌入扩域。
inline NttEngine<GoldilocksExt3>& goldilocks_ext3_engine() {
    static NttEngine<GoldilocksExt3> eng = NttEngine<GoldilocksExt3>::from_two_adic(
        GoldilocksExt3::from_base(Goldilocks::two_adic_root_of_unity(Goldilocks::TWO_ADICITY)),
        Goldilocks::TWO_ADICITY);
    return eng;
}

// generator<F>(size) — 返回域 F 的 size 阶本原单位根，
// 若引擎阶数不可被 size 整除则返回 nullopt。
//
// 分派至对应单例引擎的 checked_root()。
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
