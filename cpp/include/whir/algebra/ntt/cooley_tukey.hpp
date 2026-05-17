#pragma once

// =============================================================================
// cooley_tukey.hpp — √N Cooley-Tukey NTT 引擎 (单线程版本)。
// 对应 WHIR 中的 src/algebra/ntt/cooley_tukey.rs。
//
// C++ 端没有全局缓存 / RwLock, 每个调用方持有自己的 NttEngine<F> 实例。
// 需要 Goldilocks 域的单例引擎时, 见 cooley_tukey_goldilocks.hpp。
//
// 核心类:
//   NttEngine<F>      — NTT 引擎, 持有所在域的单位根表和预计算常量
//
// 构造:
//   make(order, omega_order)           — 直接给定 order 和对应阶的本原单位根
//   from_two_adic(root, two_adicity)   — 从 2-adic 单位根构造
//
// 正向变换:
//   ntt(values)                        — 原地 NTT, size = values.size()
//   ntt_batch(values, size)            — 批量 NTT, 每块 size 长独立变换
//
// 反向变换:
//   intt(values)                       — 原地 INTT, 不带 1/n 缩放因子
//   intt_batch(values, size)           — 批量 INTT
//
// 单位根查询:
//   root(order)                        — 返回 order 阶本原单位根 (必须存在)
//   checked_root(order)                — 返回 std::optional, 不存在时为 nullopt
//
// 自由函数:
//   apply_twiddles<F>(values, roots, rows, cols)
//     — 6-step Cooley-Tukey 中的 twiddle 因子乘法 (步骤 4)
//
// 实现细节:
//   - 小 size (0/1/2/3/4/8/16) 用硬编码展开的蝴蝶网络, 避免递归开销
//   - size=3 用 Rader 算法化为 size=2
//   - 大 size 用 √N 分解: size = n1 * n2, n1 = sqrt_factor(size)
//     6 步流程: 转置 → NTT(n1) → 转置 → Twiddle → NTT(n2) → 转置
//   - 根表 (roots_) 懒惰构造: 首次 NTT 时按 lcm 扩展
// =============================================================================

#include "transpose.hpp"
#include "utils.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

// ---- CUDA GPU 加速 (可选) ----
#ifdef WHIR_CUDA
#include "../../../../cuda/cuda_integration.hpp"
#endif

namespace whir::algebra::ntt {

// =========================================================================
// apply_twiddles<F>(values, roots, rows, cols) — twiddle 因子乘法。
//
// 这是 6-step √N Cooley-Tukey 算法的第 4 步:
//   转置后的矩阵每行 (除第 0 行和第 0 列) 需要乘以相应的 twiddle 因子。
//
// 输入:
//   values — 域元素数组, 长度为 N * (rows * cols) (可批量)
//   roots  — 单位根表, 长度是 size = rows*cols 的倍数
//   rows   — 矩阵行数 (主维)
//   cols   — 矩阵列数
//
// 算法:
//   对 values 中每个 rows×cols 子块:
//     step = roots.size() / size  (根表到当前 size 的缩放比)
//     第 0 行不变 (twiddle 因子 = 1)
//     其余行: base_index = (i * step) % roots.size()
//             第 0 列不变, 连续乘积累加 index
//             v[i][j] *= roots[index], index = (index + base_index) % roots.size()
//
// 注意: 这是原地操作, 直接修改 values。
// =========================================================================
template <typename F>
void apply_twiddles(std::span<F> values, std::span<const F> roots, std::size_t rows, std::size_t cols) {
    const std::size_t size = rows * cols;
    assert(values.size() % size == 0);
    if (size == 0) return;
    const std::size_t step = roots.size() / size;
    const std::size_t num_blocks = values.size() / size;

    // 批量中每个 block 独立, 大矩阵时并行行
    for (std::size_t off = 0; off + size <= values.size(); off += size) {
        // 只在行数足够多时启用并行, 避免递归小矩阵时的线程创建开销
        const bool do_parallel = rows >= 64;
#ifdef _OPENMP
        #pragma omp parallel for if(do_parallel)
#endif
        for (std::size_t i = 1; i < rows; ++i) {
            std::size_t base_index = (i * step) % roots.size();
            std::size_t index = base_index;
            for (std::size_t j = 1; j < cols; ++j) {
                index %= roots.size();
                values[off + i * cols + j] = values[off + i * cols + j] * roots[index];
                index += base_index;
            }
        }
    }
}

// =========================================================================
// NttEngine<F> — 单域 NTT 引擎。
//
// 持有一个域的单位根表 (roots_) 和预计算的常用单位根常量
// (omega_4_1, omega_8_1/3, omega_16_1/3/9 等), 用于展开小尺寸 NTT。
//
// 构造后不可变 (order 和 omega_order 不变), 但根表按需扩展 (懒惰初始化)。
// =========================================================================
template <typename F>
class NttEngine {
public:
    // -----------------------------------------------------------------------
    // make(order, omega_order) — 直接构造引擎。
    //
    // 输入:
    //   order       — 引擎的最大支持 NTT 长度, 必须是偶数
    //   omega_order — order 阶本原单位根 (满足 omega^order == 1,
    //                 且 omega^(order/2) != 1)
    //
    // 断言: order % 2 == 0 且 omega_order 是本原的。
    //
    // 副作用: 如果 order 能被 3/4/8/16 整除, 预计算对应的常用单位根常量,
    //         用于 size=3 的 Rader 算法和 size=4/8/16 的展开蝴蝶。
    // -----------------------------------------------------------------------
    static NttEngine make(std::size_t order, F omega_order) {
        assert(order % 2 == 0 && "order must be a multiple of 2");
        // 验证本原性: omega^order == 1 且 omega^(order/2) != 1
        assert(omega_order.pow(static_cast<uint64_t>(order)) == F::one());
        assert(!(omega_order.pow(static_cast<uint64_t>(order / 2)) == F::one()));

        NttEngine eng;
        eng.order_ = order;
        eng.omega_order_ = omega_order;

        // 预计算常用单位根常量 (用于小尺寸展开路径)。
        if (order % 3 == 0) {
            const F w3_1 = eng.root(3);
            const F w3_2 = w3_1 * w3_1;
            const F two_inv = F::from_u64(2).inverse();
            // (w3_1 ± w3_2)/2, Rader 算法的常系数
            eng.half_omega_3_1_min_2 = (w3_1 - w3_2) * two_inv;
            eng.half_omega_3_1_plus_2 = (w3_1 + w3_2) * two_inv;
        }
        if (order % 4 == 0) eng.omega_4_1 = eng.root(4);
        if (order % 8 == 0) {
            eng.omega_8_1 = eng.root(8);
            eng.omega_8_3 = eng.omega_8_1.pow(3);
        }
        if (order % 16 == 0) {
            eng.omega_16_1 = eng.root(16);
            eng.omega_16_3 = eng.omega_16_1.pow(3);
            eng.omega_16_9 = eng.omega_16_1.pow(9);
        }
        return eng;
    }

    // -----------------------------------------------------------------------
    // from_two_adic(two_adic_root, two_adicity) — 从 2-adic 单位根构造引擎。
    //
    // 输入:
    //   two_adic_root — 2^two_adicity 阶本原单位根
    //   two_adicity   — 2-adic 指数
    //
    // 如果 two_adicity ≤ 63, 直接构造 order = 2^two_adicity 的引擎。
    // 如果 two_adicity > 63, 将根连续平方直到 two_adicity 降到 63,
    // 构造 order = 2^63 的引擎 (size_t 最大 2^63, 超过无意义)。
    //
    // Goldilocks 域的 TWO_ADICITY = 32, 所以直接构造 2^32 阶引擎。
    // -----------------------------------------------------------------------
    static NttEngine from_two_adic(F two_adic_root, uint32_t two_adicity) {
        if (two_adicity <= 63) {
            return make(std::size_t{1} << two_adicity, two_adic_root);
        }
        F gen = two_adic_root;
        for (uint32_t i = 0; i < two_adicity - 63; ++i) gen = gen * gen;
        return make(std::size_t{1} << 63, gen);
    }

    std::size_t order() const noexcept { return order_; }

    // -----------------------------------------------------------------------
    // checked_root(sub_order) — 安全获取 sub_order 阶本原单位根。
    // 输入: sub_order — 需要的单位根阶数
    // 输出: std::optional<F>, 如果 order % sub_order == 0 则返回
    //       omega_order^(order/sub_order), 否则返回 std::nullopt
    // -----------------------------------------------------------------------
    std::optional<F> checked_root(std::size_t sub_order) const {
        if (order_ % sub_order != 0) return std::nullopt;
        return omega_order_.pow(static_cast<uint64_t>(order_ / sub_order));
    }

    // -----------------------------------------------------------------------
    // root(sub_order) — 获取 sub_order 阶本原单位根 (必须存在)。
    // 输入: sub_order — 需要的单位根阶数
    // 输出: F, sub_order 阶本原单位根
    // 断言: sub_order 是 order 的因子, 否则触发 assert
    // -----------------------------------------------------------------------
    F root(std::size_t sub_order) const {
        auto r = checked_root(sub_order);
        assert(r.has_value() && "subgroup of requested order does not exist");
        return *r;
    }

    // -----------------------------------------------------------------------
    // ntt(values) — 整段正向 NTT。
    // 输入: values — 域元素 span, 长度等于当前变换 size
    // 效果: 原地 NTT, 等价于 ntt_batch(values, values.size())
    // -----------------------------------------------------------------------
    void ntt(std::span<F> values) {
        ntt_batch(values, values.size());
    }

    // -----------------------------------------------------------------------
    // ntt_batch(values, size) — 批量正向 NTT。
    //
    // 输入:
    //   values — 域元素数组, 长度必须是 size 的整数倍
    //   size   — 每个子块的长度 (NTT 大小)
    //
    // 效果: 确保根表足够大 (懒惰初始化), 然后对每个 size 长的子块独立做 NTT。
    //
    // NTT 数学定义 (size=N, ω 为 N 阶本原单位根):
    //   A_k = Σ_{j=0}^{N-1} a_j · ω^{j·k}
    // -----------------------------------------------------------------------
    void ntt_batch(std::span<F> values, std::size_t size) {
        assert(values.size() % size == 0);
        ensure_roots_table(size);

        // ---- GPU 加速: 大矩阵 NTT 卸到 GPU ----
#ifdef WHIR_CUDA
        if (values.size() >= whir::cuda::GPU_NTT_THRESHOLD) {
            auto& pool = whir::cuda::GpuPool::instance();
            if (pool.roots_len() != roots_.size())
                pool.upload_roots(reinterpret_cast<const uint64_t*>(roots_.data()), roots_.size());
            whir::cuda::gpu_ntt_batch(
                reinterpret_cast<uint64_t*>(values.data()),
                reinterpret_cast<const uint64_t*>(roots_.data()),
                values.size(), size);
            return;
        }
#endif
        const std::size_t num_blocks = values.size() / size;
#ifdef _OPENMP
        if (num_blocks > 1 && size >= 1024) {
            #pragma omp parallel for
            for (std::ptrdiff_t bi = 0; bi < static_cast<std::ptrdiff_t>(num_blocks); ++bi) {
                F* block = values.data() + static_cast<std::size_t>(bi) * size;
                ntt_dispatch(std::span<F>{block, size}, std::span<const F>{roots_}, size);
            }
            return;
        }
#endif
        ntt_dispatch(values, std::span<const F>{roots_}, size);
    }

    // -----------------------------------------------------------------------
    // intt(values) — 整段反向 NTT (不带 1/n 缩放)。
    //
    // 输入: values — 域元素 span, 长度等于当前变换 size
    // 效果: 原地 INTT, 等价于先反转 [1..] 再做正向 NTT。
    // 注意: 不包含 1/n 缩放因子, 调用方需要手动除以 n。
    //
    // INTT 数学定义:
    //   a_j = (1/N) · Σ_{k=0}^{N-1} A_k · ω^{-j·k}
    // 此处省略了 1/N 因子, 只计算 Σ 部分。
    // -----------------------------------------------------------------------
    void intt(std::span<F> values) {
        if (values.size() > 1) {
            std::size_t i = 1, j = values.size() - 1;
            while (i < j) {
                std::swap(values[i], values[j]);
                ++i; --j;
            }
        }
        ntt(values);
    }

    // -----------------------------------------------------------------------
    // intt_batch(values, size) — 批量反向 NTT (不带 1/n 缩放)。
    // 输入: values — 长度是 size 的整数倍; size — 每块大小
    // 效果: 每块独立做 INTT (反转 [1..size-1] 后正向 NTT)
    // -----------------------------------------------------------------------
    void intt_batch(std::span<F> values, std::size_t size) {
        assert(values.size() % size == 0);
        for (std::size_t off = 0; off + size <= values.size(); off += size) {
            std::size_t i = 1, j = size - 1;
            while (i < j) {
                std::swap(values[off + i], values[off + j]);
                ++i; --j;
            }
        }
        ntt_batch(values, size);
    }

private:
    NttEngine() = default;

    // -----------------------------------------------------------------------
    // ensure_roots_table(order) — 确保根表包含至少 order 个元素。
    //
    // 懒惰初始化策略:
    //   - 首次调用时构造恰好 order 个根: [ω^0, ω^1, ..., ω^(order-1)]
    //   - 后续如果要求更大的 order, 通过 lcm 扩展:
    //     新建 lcm(当前size, order) 大小的表, 重新计算全部根
    //
    // 根表存储 ω^(order/size) 的各次幂, 用于所有 NTT 子变换。
    // -----------------------------------------------------------------------
    void ensure_roots_table(std::size_t order) {
        if (roots_.empty() || roots_.size() % order != 0) {
            const std::size_t size = roots_.empty() ? order : lcm(roots_.size(), order);
            roots_.clear();
            roots_.reserve(size);
            const F r = root(size);
            F acc = F::one();
            for (std::size_t i = 0; i < size; ++i) {
                roots_.push_back(acc);
                acc = acc * r;
            }
        }
    }

    // -----------------------------------------------------------------------
    // ntt_recurse(values, roots, size) — √N Cooley-Tukey 递归步骤。
    //
    // 6 步算法:
    //   1. transpose: 把数据视为 n1×n2 矩阵并转置为 n2×n1
    //   2. NTT(n1):   对每行 (长度 n1) 做 NTT
    //   3. transpose: 转置回 n1×n2
    //   4. Twiddle:   逐元素乘以 twiddle 因子
    //   5. NTT(n2):   对每行 (长度 n2) 做 NTT
    //   6. transpose: 转置为 n2×n1 (最终排列)
    //
    // 其中 n1 = sqrt_factor(size), n2 = size / n1。
    // -----------------------------------------------------------------------
    void ntt_recurse(std::span<F> values, std::span<const F> roots, std::size_t size) {
        assert(values.size() % size == 0);
        const std::size_t n1 = sqrt_factor(size);
        const std::size_t n2 = size / n1;
        transpose<F>(values, n1, n2);
        ntt_dispatch(values, roots, n1);
        transpose<F>(values, n2, n1);
        apply_twiddles<F>(values, roots, n1, n2);
        ntt_dispatch(values, roots, n2);
        transpose<F>(values, n1, n2);
    }

    // -----------------------------------------------------------------------
    // ntt_dispatch(values, roots, size) — NTT 分发器。
    //
    // 输入:
    //   values — 域元素数组, 长度是 size 的倍数
    //   roots  — 根表 (长度是 size 的倍数)
    //   size   — 每块大小
    //
    // 根据 size 选择最优实现:
    //   size=0/1: 恒等 (无需操作)
    //   size=2:   二阶蝴蝶: a'=a+b, b'=a-b
    //   size=3:   Rader 算法 (化为 size=2 的 NTT)
    //   size=4:   四阶 Cooley-Tukey 展开 (两层蝴蝶)
    //   size=8:   八阶展开 (三层蝴蝶 + twiddle)
    //   size=16:  十六阶展开 (4×4 复合 with 转置)
    //   default:  → ntt_recurse (√N 递归)
    //
    // 断言: values.size() % size == 0 且 roots.size() % size == 0
    // -----------------------------------------------------------------------
    void ntt_dispatch(std::span<F> values, std::span<const F> roots, std::size_t size) {
        assert(values.size() % size == 0);
        assert(roots.size() % size == 0);
        switch (size) {
            case 0:
            case 1:
                // 空或单元素: 恒等变换。
                return;
            case 2: {
                // 二阶蝴蝶: [a, b] → [a+b, a-b]
                for (std::size_t off = 0; off + 2 <= values.size(); off += 2) {
                    F a = values[off + 0];
                    F b = values[off + 1];
                    values[off + 0] = a + b;
                    values[off + 1] = a - b;
                }
                return;
            }
            case 3: {
                // Rader 算法: 把 size=3 的 NTT 化为 size=2 (极少使用, 不并行化)。
                for (std::size_t off = 0; off + 3 <= values.size(); off += 3) {
                    F* v = values.data() + off;
                    const F v0 = v[0];
                    F t1 = v[1] + v[2];
                    F t2 = v[1] - v[2];
                    v[1] = t1;
                    v[2] = t2;
                    v[0] = v[0] + v[1];
                    v[1] = v[1] * half_omega_3_1_plus_2;
                    v[2] = v[2] * half_omega_3_1_min_2;
                    v[1] = v[1] + v0;
                    F u1 = v[1] + v[2];
                    F u2 = v[1] - v[2];
                    v[1] = u1;
                    v[2] = u2;
                }
                return;
            }
            case 4: {
                // 四阶 Cooley-Tukey: 两层蝴蝶 + 一次 twiddle (ω₄)。
                for (std::size_t off = 0; off + 4 <= values.size(); off += 4) {
                    F* v = values.data() + off;
                    F a02p = v[0] + v[2], a02m = v[0] - v[2];
                    F a13p = v[1] + v[3], a13m = v[1] - v[3];
                    v[0] = a02p; v[2] = a02m;
                    v[1] = a13p; v[3] = a13m;
                    v[3] = v[3] * omega_4_1;
                    F b01p = v[0] + v[1], b01m = v[0] - v[1];
                    F b23p = v[2] + v[3], b23m = v[2] - v[3];
                    v[0] = b01p; v[1] = b01m;
                    v[2] = b23p; v[3] = b23m;
                    std::swap(v[1], v[2]);
                }
                return;
            }
            case 8: {
                // 八阶 Cooley-Tukey: 三层蝴蝶 + twiddle (ω₈, ω₄)。
                // 阶段 1: 按 4 分离再组合 (奇偶分离)
                // 阶段 2: 乘 twiddle ω₈¹, ω₄(=ω₈²), ω₈³
                // 阶段 3: 前半/后半各自 size=4 的后续
                // 最后位逆序交换: swap(1,4), swap(3,6)
                for (std::size_t off = 0; off + 8 <= values.size(); off += 8) {
                    F* v = values.data() + off;
                    {
                        F a0 = v[0] + v[4], a4 = v[0] - v[4]; v[0]=a0; v[4]=a4;
                        F a1 = v[1] + v[5], a5 = v[1] - v[5]; v[1]=a1; v[5]=a5;
                        F a2 = v[2] + v[6], a6 = v[2] - v[6]; v[2]=a2; v[6]=a6;
                        F a3 = v[3] + v[7], a7 = v[3] - v[7]; v[3]=a3; v[7]=a7;
                    }
                    v[5] = v[5] * omega_8_1;
                    v[6] = v[6] * omega_4_1; // ω₈² = ω₄
                    v[7] = v[7] * omega_8_3;
                    {
                        F a0 = v[0] + v[2], a2 = v[0] - v[2]; v[0]=a0; v[2]=a2;
                        F a1 = v[1] + v[3], a3 = v[1] - v[3]; v[1]=a1; v[3]=a3;
                    }
                    v[3] = v[3] * omega_4_1;
                    {
                        F a0 = v[0] + v[1], a1 = v[0] - v[1]; v[0]=a0; v[1]=a1;
                        F a2 = v[2] + v[3], a3 = v[2] - v[3]; v[2]=a2; v[3]=a3;
                        F a4 = v[4] + v[6], a6 = v[4] - v[6]; v[4]=a4; v[6]=a6;
                        F a5 = v[5] + v[7], a7 = v[5] - v[7]; v[5]=a5; v[7]=a7;
                    }
                    v[7] = v[7] * omega_4_1;
                    {
                        F a4 = v[4] + v[5], a5 = v[4] - v[5]; v[4]=a4; v[5]=a5;
                        F a6 = v[6] + v[7], a7 = v[6] - v[7]; v[6]=a6; v[7]=a7;
                    }
                    std::swap(v[1], v[4]);
                    std::swap(v[3], v[6]);
                }
                return;
            }
            case 16: {
                // 十六阶 Cooley-Tukey: 4×4 复合 NTT。
                // 把 16 个元素视为 4×4 矩阵:
                //   阶段 1: 对每列做 size=4 的 NTT
                //   阶段 2: 逐元素乘 twiddle 矩阵 (ω₁₆ 的各次幂)
                //   阶段 3: 对每行做 size=4 的 NTT
                //   阶段 4: 4×4 转置 (固定交换模式)
                for (std::size_t off = 0; off + 16 <= values.size(); off += 16) {
                    F* base = values.data() + off;
                    // 阶段 1: 列 NTT (4 列, 每列 4 元素, stride=4)。
                    for (std::size_t i = 0; i < 4; ++i) {
                        F* v = base + i;
                        F t0p = v[0] + v[8], t0m = v[0] - v[8]; v[0]=t0p; v[8]=t0m;
                        F t4p = v[4] + v[12], t4m = v[4] - v[12]; v[4]=t4p; v[12]=t4m;
                        v[12] = v[12] * omega_4_1;
                        F u0p = v[0] + v[4], u0m = v[0] - v[4]; v[0]=u0p; v[4]=u0m;
                        F u8p = v[8] + v[12], u8m = v[8] - v[12]; v[8]=u8p; v[12]=u8m;
                        std::swap(v[4], v[8]);
                    }
                    // 阶段 2: twiddle 乘法 (ω₁₆ 矩阵)。
                    base[5]  = base[5]  * omega_16_1;
                    base[6]  = base[6]  * omega_8_1;
                    base[7]  = base[7]  * omega_16_3;
                    base[9]  = base[9]  * omega_8_1;
                    base[10] = base[10] * omega_4_1;
                    base[11] = base[11] * omega_8_3;
                    base[13] = base[13] * omega_16_3;
                    base[14] = base[14] * omega_8_3;
                    base[15] = base[15] * omega_16_9;
                    // 阶段 3: 行 NTT (4 行, 每行 4 元素连续)。
                    for (std::size_t i = 0; i < 4; ++i) {
                        F* v = base + i * 4;
                        F a02p = v[0] + v[2], a02m = v[0] - v[2];
                        F a13p = v[1] + v[3], a13m = v[1] - v[3];
                        v[0]=a02p; v[2]=a02m;
                        v[1]=a13p; v[3]=a13m;
                        v[3] = v[3] * omega_4_1;
                        F b01p = v[0] + v[1], b01m = v[0] - v[1];
                        F b23p = v[2] + v[3], b23m = v[2] - v[3];
                        v[0]=b01p; v[1]=b01m;
                        v[2]=b23p; v[3]=b23m;
                        std::swap(v[1], v[2]);
                    }
                    // 阶段 4: 4×4 转置 (固定模式, 来自 Rust 实现)。
                    std::swap(base[1],  base[4]);
                    std::swap(base[2],  base[8]);
                    std::swap(base[3],  base[12]);
                    std::swap(base[6],  base[9]);
                    std::swap(base[7],  base[13]);
                    std::swap(base[11], base[14]);
                }
                return;
            }
            default:
                // 大尺寸: √N 递归分解。
                ntt_recurse(values, roots, size);
                return;
        }
    }

    // ---- 成员变量 ----

    std::size_t order_ = 0;             // 引擎最大 NTT 长度
    F omega_order_ = F::zero();         // order 阶本原单位根

    // 预计算的常用单位根常量 (用于小尺寸展开):
    F half_omega_3_1_plus_2 = F::zero(); // (ω₃ + ω₃²)/2 (Rader size=3)
    F half_omega_3_1_min_2 = F::zero();  // (ω₃ - ω₃²)/2 (Rader size=3)
    F omega_4_1 = F::zero();             // ω₄¹ (4 阶根, 即 -1 的平方根)
    F omega_8_1 = F::zero();             // ω₈¹
    F omega_8_3 = F::zero();             // ω₈³ (= ω₈¹ 的三次方)
    F omega_16_1 = F::zero();            // ω₁₆¹
    F omega_16_3 = F::zero();            // ω₁₆³
    F omega_16_9 = F::zero();            // ω₁₆⁹

    // 根表: 存储某个 size 的全部单位根 [ω^0, ω^1, ..., ω^(size-1)]
    // 懒惰初始化, 按 lcm 自动扩展。
    std::vector<F> roots_;
};

// Rust 顶层的 ntt / intt / ntt_batch / intt_batch / generator 在 C++ 端
// 不再以全局缓存形式提供; 调用方持有 NttEngine<F> 实例即可。
// 需要 Goldilocks 域的单例引擎时, 见 cooley_tukey_goldilocks.hpp。

} // namespace whir::algebra::ntt
