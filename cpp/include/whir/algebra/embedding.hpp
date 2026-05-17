#pragma once

// 对应 WHIR 中的 src/algebra/embedding.rs。
// Rust 侧用 trait Embedding 表示一个从 Source 域到 Target 域的环同态,
// C++ 侧直接用模板结构体,每种 embedding 暴露两个类型别名 Source/Target 和
// 三个方法 map/mixed_mul/mixed_add,行为和 Rust 完全一致。
//
// 本期仅移植 Identity 和 Basefield, Rust 中的 Frobenius/Compose 不被本期使用,暂不移植。

#include "goldilocks.hpp"
#include "goldilocks_ext2.hpp"
#include "goldilocks_ext3.hpp"

#include <vector>

namespace whir::algebra {

// 恒等嵌入 F -> F
template <typename F>
struct Identity { //恒等类型
    using Source = F;
    using Target = F;

    static constexpr F map(const F& x) noexcept { return x; } //原封返回
    static constexpr F mixed_mul(const F& cod, const F& dom) noexcept { return cod * dom; } //返回相乘
    static constexpr F mixed_add(const F& cod, const F& dom) noexcept { return cod + dom; } //返回相加
    static std::vector<F> map_vec(std::vector<F> src) { return src; } //输入一个向量，返回一个向量
};

// 基域嵌入 Base -> Ext (其中 Ext::BaseField == Base)
template <typename Ext>
struct Basefield {
    using Source = typename Ext::BaseField; //前面要加一个typename,表示访问的是类型名称不是普通变量
    using Target = Ext;

    //假设从Goldilocks->Goldilocks_Ext2
    static Ext map(const Source& x) noexcept { return Ext::from_base(x); }

    // Rust 侧在 mul_by_base_prime_field 里做了优化, 避免构造完整的扩域元素再做乘法。
    // C++ 这里手动按系数逐个乘,效果相同且避免了多余的 0 乘。
    static Ext mixed_mul(const Ext& cod, const Source& dom) noexcept {
        return mixed_mul_impl(cod, dom);
    }

    //先调用map把dom变为扩域元素(b,0)再相加
    static Ext mixed_add(const Ext& cod, const Source& dom) noexcept {
        return cod + map(dom);
    }

    static std::vector<Ext> map_vec(const std::vector<Source>& src) {
        std::vector<Ext> out;
        out.reserve(src.size()); //提前分配好一个向量大小
        for (const auto& v : src) out.push_back(map(v)); //通过map转换为Goldilocks_Ext2域元素
        return out;
    }

private:
    //针对 Ext2 的标量乘: (c0, c1) * b = (c0 b, c1 b)
    static GoldilocksExt2 mixed_mul_impl(const GoldilocksExt2& cod, const Goldilocks& b) noexcept {
        return {cod.c0() * b, cod.c1() * b};
    }

    //针对 Ext3 的标量乘: (c0, c1, c2) * b = (c0 b, c1 b, c2 b)
    static GoldilocksExt3 mixed_mul_impl(const GoldilocksExt3& cod, const Goldilocks& b) noexcept {
        return {cod.c0() * b, cod.c1() * b, cod.c2() * b};
    }
};

} // namespace whir::algebra
