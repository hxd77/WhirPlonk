#pragma once

// ============================================================================
// embedding.hpp — 域扩张之间的环同态
//
// Embedding 将元素从 Source 域映射到 Target 域，同时保持环运算。
// 每个嵌入暴露:
//   map(x)            — 应用同态映射
//   mixed_mul(cod, dom) — Target * Source 乘法
//   mixed_add(cod, dom) — Target + Source 加法
//   map_vec(src)      — 向量逐元素映射
//
// 具体嵌入:
//   Identity<F>    — F -> F（平凡映射）
//   Basefield<Ext> — Ext::BaseField -> Ext（逐系数提升）
//
// 对应 WHIR Rust: src/algebra/embedding.rs
// 仅移植 Identity 和 Basefield；Frobenius/Compose 未使用。
// ============================================================================

#include "goldilocks.hpp"
#include "goldilocks_ext2.hpp"
#include "goldilocks_ext3.hpp"

#include <vector>

namespace whir::algebra {

// 恒等嵌入: F -> F，所有操作直接透传。
template <typename F>
struct Identity {
    using Source = F;
    using Target = F;

    static constexpr F map(const F& x) noexcept { return x; }
    static constexpr F mixed_mul(const F& cod, const F& dom) noexcept { return cod * dom; }
    static constexpr F mixed_add(const F& cod, const F& dom) noexcept { return cod + dom; }
    static std::vector<F> map_vec(std::vector<F> src) { return src; }
};

// 基域嵌入: Base -> Ext，其中 Ext::BaseField == Base。
// 通过 Ext::from_base 将基域元素提升到扩域。
template <typename Ext>
struct Basefield {
    using Source = typename Ext::BaseField;
    using Target = Ext;

    static Ext map(const Source& x) noexcept { return Ext::from_base(x); }

    // 逐系数标量乘法，避免构造完整的扩域元素。
    // 分派到下面的类型特化重载。
    static Ext mixed_mul(const Ext& cod, const Source& dom) noexcept {
        return mixed_mul_impl(cod, dom);
    }

    // 提升 dom 到扩域后相加: cod + map(dom)。
    static Ext mixed_add(const Ext& cod, const Source& dom) noexcept {
        return cod + map(dom);
    }

    static std::vector<Ext> map_vec(const std::vector<Source>& src) {
        std::vector<Ext> out;
        out.reserve(src.size());
        for (const auto& v : src) out.push_back(map(v));
        return out;
    }

private:
    // Ext2 标量乘法: (c0, c1) * b = (c0*b, c1*b)
    static GoldilocksExt2 mixed_mul_impl(const GoldilocksExt2& cod, const Goldilocks& b) noexcept {
        return {cod.c0() * b, cod.c1() * b};
    }

    // Ext3 标量乘法: (c0, c1, c2) * b = (c0*b, c1*b, c2*b)
    static GoldilocksExt3 mixed_mul_impl(const GoldilocksExt3& cod, const Goldilocks& b) noexcept {
        return {cod.c0() * b, cod.c1() * b, cod.c2() * b};
    }
};

} // namespace whir::algebra
