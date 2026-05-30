#pragma once

// ============================================================================
// cooley_tukey.hpp — √N Cooley-Tukey NTT 引擎
//
// 使用 radix-√N Cooley-Tukey 分解实现有限域上的原地 NTT。
// 对于 N = n1 × n2，其中 n1 = sqrt_factor(N)，6 步算法为：
//   1. 转置输入为 n2 × n1 矩阵
//   2. 对每行执行 NTT(n1)
//   3. 转置回 n1 × n2
//   4. 乘以 twiddle 因子 ω^(i·j·step)
//   5. 对每行执行 NTT(n2)
//   6. 最终转置
//
// 小规模变换（2, 3, 4, 8, 16）使用展开的蝶形网络，无递归开销。
// 规模 3 使用 Rader 算法归约至规模 2 的 NTT。
// 根表按需通过 lcm 惰性扩展。
//
// 单线程实现，无全局缓存。Goldilocks 域的单例引擎见
// cooley_tukey_goldilocks.hpp。
//
// 对应 Rust 源文件：src/algebra/ntt/cooley_tukey.rs
// ============================================================================

#include "transpose.hpp"
#include "utils.hpp"
#include "../goldilocks_ext2.hpp"
#include "../goldilocks_ext3.hpp"
#include "../../hash/hash_engine.hpp"
#include "../../profiling.hpp"

#include <cassert>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

// ---- 可选 CUDA 加速 ----
#ifdef WHIR_CUDA
#include "../../../../cuda/cuda_integration.hpp"
#endif

namespace whir::algebra {
class Goldilocks;
class GoldilocksExt3;
}

namespace whir::algebra::ntt {

template <typename F>
F mul_by_root(const F& value, const F& root) noexcept {
    return value * root;
}

inline GoldilocksExt2 mul_by_root(const GoldilocksExt2& value, const GoldilocksExt2& root) noexcept {
    if (root.c1().is_zero()) {
        const Goldilocks scalar = root.c0();
        return {value.c0() * scalar, value.c1() * scalar};
    }
    return value * root;
}

inline GoldilocksExt3 mul_by_root(const GoldilocksExt3& value, const GoldilocksExt3& root) noexcept {
    if (root.c1().is_zero() && root.c2().is_zero()) {
        const Goldilocks scalar = root.c0();
        return {value.c0() * scalar, value.c1() * scalar, value.c2() * scalar};
    }
    return value * root;
}

// ============================================================================
// apply_twiddles — 6 步 Cooley-Tukey 算法第 4 步
//
// 对矩阵 v[i][j]（i > 0, j > 0）乘以 twiddle 因子 ω^(i·j·step)，
// 其中 step = roots.size() / (rows × cols)。
//
// 前置条件：
//   - values.size() 是 rows × cols 的整数倍
//   - roots.size() 是 rows × cols 的整数倍
//
// 副作用：原地修改 values。当 rows ≥ 64 时通过 OpenMP 按行并行化。
// ============================================================================
template <typename F>
void apply_twiddles(std::span<F> values, std::span<const F> roots, std::size_t rows, std::size_t cols) {
    const std::size_t size = rows * cols;
    assert(values.size() % size == 0);
    if (size == 0) return;
    const std::size_t step = roots.size() / size;
    const std::size_t num_blocks = values.size() / size;

    for (std::size_t off = 0; off + size <= values.size(); off += size) {
        // 矩阵足够大时启用行级并行，以摊销线程创建开销
        const bool do_parallel = rows >= 64;
#ifdef _OPENMP
        #pragma omp parallel for if(do_parallel)
#endif
        for (std::ptrdiff_t si = 1; si < static_cast<std::ptrdiff_t>(rows); ++si) {
            std::size_t i = static_cast<std::size_t>(si);
            std::size_t base_index = (i * step) % roots.size();
            std::size_t index = base_index;
            for (std::size_t j = 1; j < cols; ++j) {
                index %= roots.size();
                values[off + i * cols + j] = mul_by_root(values[off + i * cols + j], roots[index]);
                index += base_index;
            }
        }
    }
}

// ============================================================================
// NttEngine<F> — 单域 NTT 引擎
//
// 持有单位根表和小规模展开所需的预计算常量。
// 通过 make() 或 from_two_adic() 构造；构造后不可变（根表惰性扩展除外）。
// ============================================================================
template <typename F>
class NttEngine {
public:
    // 使用显式阶数和本原单位根构造引擎。
    //
    // 前置条件：
    //   - order 为偶数
    //   - omega_order^order == 1 且 omega_order^(order/2) != 1
    //
    // 副作用：当 order 可被 3, 4, 8, 16 整除时，预计算对应根常量。
    static NttEngine make(std::size_t order, F omega_order) {
        assert(order % 2 == 0 && "order must be a multiple of 2");
        assert(omega_order.pow(static_cast<uint64_t>(order)) == F::one());
        assert(!(omega_order.pow(static_cast<uint64_t>(order / 2)) == F::one()));

        NttEngine eng;
        eng.order_ = order;
        eng.omega_order_ = omega_order;

        // 预计算小规模展开路径所需的常量
        if (order % 3 == 0) {
            const F w3_1 = eng.root(3);
            const F w3_2 = w3_1 * w3_1;
            const F two_inv = F::from_u64(2).inverse();
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

    // 从 2-adic 本原单位根构造引擎。
    //
    // 若 two_adicity ≤ 63，直接构造阶为 2^two_adicity 的引擎。
    // 若 two_adicity > 63，反复平方直到指数降至 63（size_t 无法表示 2^63 以上的阶）。
    static NttEngine from_two_adic(F two_adic_root, uint32_t two_adicity) {
        if (two_adicity <= 63) {
            return make(std::size_t{1} << two_adicity, two_adic_root);
        }
        F gen = two_adic_root;
        for (uint32_t i = 0; i < two_adicity - 63; ++i) gen = gen * gen;
        return make(std::size_t{1} << 63, gen);
    }

    std::size_t order() const noexcept { return order_; }

    // 返回 sub_order 阶本原单位根；若 order 不可被 sub_order 整除则返回 nullopt。
    std::optional<F> checked_root(std::size_t sub_order) const {
        if (order_ % sub_order != 0) return std::nullopt;
        return omega_order_.pow(static_cast<uint64_t>(order_ / sub_order));
    }

    // 返回 sub_order 阶本原单位根。断言 order 可被 sub_order 整除。
    F root(std::size_t sub_order) const {
        auto r = checked_root(sub_order);
        assert(r.has_value() && "subgroup of requested order does not exist");
        return *r;
    }

    // 对整个 span 执行正向 NTT，等价于 ntt_batch(values, values.size())。
    void ntt(std::span<F> values) {
        ntt_batch(values, values.size());
    }

    // 批量正向 NTT：每个连续的 size 元素块独立变换。
    //
    // NTT 定义（规模 N，ω 为 N 阶本原单位根）：
    //   A_k = Σ_{j=0}^{N-1} a_j · ω^(j·k)
    //
    // 副作用：按需惰性扩展根表。
    void ntt_batch(std::span<F> values, std::size_t size) {
        assert(values.size() % size == 0);
        ensure_roots_table(size);

        // 大规模 Goldilocks 批量运算卸载至 GPU
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        if constexpr (std::is_same_v<F, whir::algebra::Goldilocks>) {
        if (whir::cuda::gpu_dispatch_enabled() &&
            values.size() >= whir::cuda::gpu_ntt_threshold()) {
            if (whir::profile::cuda_trace_enabled()) {
                std::fprintf(stderr,
                    "[CUDA NTT] using GPU fast path: total_elements=%zu size=%zu batch=%zu\n",
                    values.size(), size, values.size() / size);
            }
            auto& pool = whir::cuda::GpuPool::instance();
            if (pool.roots_len() != roots_.size() || pool.roots_host() != reinterpret_cast<const uint64_t*>(roots_.data()))
                pool.upload_roots(reinterpret_cast<const uint64_t*>(roots_.data()), roots_.size());
            whir::cuda::gpu_ntt_batch(
                reinterpret_cast<uint64_t*>(values.data()),
                reinterpret_cast<const uint64_t*>(roots_.data()),
                values.size(), size);
            return;
        }
        if (whir::profile::cuda_trace_enabled()) {
            std::fprintf(stderr,
                "[CUDA NTT] CPU fallback: total_elements=%zu size=%zu threshold=%zu enabled=%d\n",
                values.size(), size, whir::cuda::gpu_ntt_threshold(),
                whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
        }
        } else {
            whir::profile::cuda_trace("[CUDA NTT] CPU fallback: GPU fast path only supports Goldilocks base field");
        }
#endif
        const std::size_t num_blocks = values.size() / size;
        if (is_power_of_two(size) && size >= 32) {
#ifdef _OPENMP
            if (num_blocks > 1 && size >= 1024) {
                #pragma omp parallel for schedule(static)
                for (std::ptrdiff_t bi = 0; bi < static_cast<std::ptrdiff_t>(num_blocks); ++bi) {
                    F* block = values.data() + static_cast<std::size_t>(bi) * size;
                    ntt_power_of_two(std::span<F>{block, size}, std::span<const F>{roots_});
                }
                return;
            }
#endif
            ntt_power_of_two(values, std::span<const F>{roots_}, size);
            return;
        }
#ifdef _OPENMP
        if (num_blocks > 1 && size >= 1024) {
            #pragma omp parallel for schedule(static)
            for (std::ptrdiff_t bi = 0; bi < static_cast<std::ptrdiff_t>(num_blocks); ++bi) {
                F* block = values.data() + static_cast<std::size_t>(bi) * size;
                ntt_dispatch(std::span<F>{block, size}, std::span<const F>{roots_}, size);
            }
            return;
        }
#endif
        ntt_dispatch(values, std::span<const F>{roots_}, size);
    }

    // 尝试在 GPU 上执行融合 NTT + 转置。若成功卸载则返回 true。
    bool try_gpu_ntt_batch_transpose(
        std::span<F> values,
        std::size_t ntt_size,
        std::size_t rows,
        std::size_t cols
    ) {
        assert(values.size() == rows * cols);
        assert(values.size() % ntt_size == 0);
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        if constexpr (std::is_same_v<F, whir::algebra::Goldilocks>) {
            if (whir::cuda::gpu_dispatch_enabled() &&
                values.size() >= whir::cuda::gpu_ntt_threshold()) {
                if (whir::profile::cuda_trace_enabled()) {
                    std::fprintf(stderr,
                        "[CUDA NTT] using GPU fast path with transpose: total_elements=%zu ntt_size=%zu rows=%zu cols=%zu\n",
                        values.size(), ntt_size, rows, cols);
                }
                ensure_roots_table(ntt_size);
                auto& pool = whir::cuda::GpuPool::instance();
                if (pool.roots_len() != roots_.size() ||
                    pool.roots_host() != reinterpret_cast<const uint64_t*>(roots_.data())) {
                    pool.upload_roots(reinterpret_cast<const uint64_t*>(roots_.data()), roots_.size());
                }
                whir::cuda::gpu_ntt_batch_transpose(
                    reinterpret_cast<uint64_t*>(values.data()),
                    reinterpret_cast<const uint64_t*>(roots_.data()),
                    values.size(), ntt_size, rows, cols);
                return true;
            }
            if (whir::profile::cuda_trace_enabled()) {
                std::fprintf(stderr,
                    "[CUDA NTT] transpose CPU fallback: total_elements=%zu ntt_size=%zu threshold=%zu enabled=%d\n",
                    values.size(), ntt_size, whir::cuda::gpu_ntt_threshold(),
                    whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
            }
        } else {
            whir::profile::cuda_trace("[CUDA NTT] transpose CPU fallback: GPU fast path only supports Goldilocks base field");
        }
#else
        (void)values;
        (void)ntt_size;
        (void)rows;
        (void)cols;
#endif
        return false;
    }

    // 尝试在 GPU 上执行 Reed-Solomon 编码的零填充/批量 NTT/最终转置。
    bool try_gpu_interleaved_rs_encode(
        std::span<const std::span<const F>> coeffs,
        std::size_t codeword_length,
        std::size_t interleaving_depth,
        std::vector<F>& out
    ) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        //只支持Goldilocks
        if constexpr (std::is_same_v<F, whir::algebra::Goldilocks>) {
            if (coeffs.empty()) {
                out.clear();
                return true;
            }
            const std::size_t poly_size = coeffs[0].size();
            const std::size_t total_size = coeffs.size() * interleaving_depth * codeword_length; //总元素个数

            //GPU没开启或数据量太小,不走GPU
            if (!whir::cuda::gpu_dispatch_enabled() ||
                total_size < whir::cuda::gpu_ntt_threshold()) {
                //不走GPU，打印fallback信息
                if (whir::profile::cuda_trace_enabled()) {
                    std::fprintf(stderr,
                        "[CUDA RS] CPU fallback: num_polys=%zu poly_size=%zu codeword_length=%zu interleaving_depth=%zu total_elements=%zu threshold=%zu enabled=%d\n",
                        coeffs.size(), poly_size, codeword_length, interleaving_depth,
                        total_size, whir::cuda::gpu_ntt_threshold(),
                        whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
                }
                return false;
            }

            //如果可以走GPU，打印GPU fast path路径
            if (whir::profile::cuda_trace_enabled()) {
                std::fprintf(stderr,
                    "[CUDA RS] using GPU fast path: num_polys=%zu poly_size=%zu codeword_length=%zu interleaving_depth=%zu total_elements=%zu\n",
                    coeffs.size(), poly_size, codeword_length, interleaving_depth, total_size);
            }

            //准备长度为codeword_length的单位根表
            ensure_roots_table(codeword_length);
            //获取GPU资源池
            auto& pool = whir::cuda::GpuPool::instance();
            //如果GPU资源池中的roots与这次不匹配，就重新上传
            //长度不一样或者host指针不一样(GPU pool 记录的那张 CPU roots 表地址，是否和当前 roots_.data() 一样。)
            if (pool.roots_len() != roots_.size() ||
                pool.roots_host() != reinterpret_cast<const uint64_t*>(roots_.data())) {
                pool.upload_roots(reinterpret_cast<const uint64_t*>(roots_.data()), roots_.size()); //把CPU里的root_拷贝进GPU显存
            }

            std::vector<F> compact;
            compact.reserve(coeffs.size() * poly_size);
            //把多个coeffs压平成一段连续内存
            /*
            coeffs = [
    `               [a0, a1, a2, a3],
    `               [b0, b1, b2, b3],  ->
    `               [c0, c1, c2, c3]
                ]
            compact = [
                    a0, a1, a2, a3,
                    b0, b1, b2, b3,
                    c0, c1, c2, c3
                ]
             */
            for (const auto& poly : coeffs) {
                compact.insert(compact.end(), poly.begin(), poly.end());
            }

            //分配输出空间
            out.resize(total_size);
            whir::cuda::gpu_interleaved_rs_encode( //进入gpu_interleaved_rs_encode
                reinterpret_cast<const uint64_t*>(compact.data()),
                reinterpret_cast<uint64_t*>(out.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);
            return true;
        }

        //如果有Goldilocks64_Ext3域,GoldilocksExt=c0+c1*u+c2*u^2
        else if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt3>) {
            //如果输入为空，直接清空输出
            if (coeffs.empty()) {
                out.clear();
                return true;
            }
            const std::size_t poly_size = coeffs[0].size();  //每个多项式原始系数数量
            const std::size_t total_size = coeffs.size() * interleaving_depth * codeword_length; //最终编码输出的GoldilocksExt3个元素
            if (!whir::cuda::gpu_dispatch_enabled() || //是否启用GPU: GPU dispatch没开或者数据量太小不启用cuda
                total_size < whir::cuda::gpu_ntt_threshold()) {
                if (whir::profile::cuda_trace_enabled()) {  //是否开启了cuda_trace_enabled
                    std::fprintf(stderr,
                        "[CUDA RS Ext3] CPU fallback: num_polys=%zu poly_size=%zu codeword_length=%zu interleaving_depth=%zu total_elements=%zu threshold=%zu enabled=%d\n",
                        coeffs.size(), poly_size, codeword_length, interleaving_depth,
                        total_size, whir::cuda::gpu_ntt_threshold(),
                        whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
                }
                //如果开启了CUDA trace
                //打印类似
                //[CUDA RS Ext3] CPU fallback: num_polys=2 poly_size=4 codeword_length=8 interleaving_depth=3 total_elements=48 threshold=4096 enabled=1
                return false; //GPU快路径没有处理成功，外层走CPU版本
            }

            //走GPU快路径时的打印信息
            //[CUDA RS Ext3] using GPU fast path via 3 Goldilocks component NTTs
            //把GoldilocksExt3元素拆成3个Goldilocks分量，然后做3次Goldilocks NTT
            if (whir::profile::cuda_trace_enabled()) {
                std::fprintf(stderr,
                    "[CUDA RS Ext3] using GPU fast path via 3 Goldilocks component NTTs: num_polys=%zu poly_size=%zu codeword_length=%zu interleaving_depth=%zu total_elements=%zu\n",
                    coeffs.size(), poly_size, codeword_length, interleaving_depth, total_size);
            }

            //准备roots表,比如codeword_length=8,那需要长度为8的NTT roots
            ensure_roots_table(codeword_length);
            std::vector<whir::algebra::Goldilocks> base_roots;
            base_roots.reserve(roots_.size());
            for (const auto& root : roots_) {
                base_roots.push_back(root.c0()); //取c0放到base_roots ,NTT用到的单位根本身来自Goldilocks基域
            }

            //上传roots到GPU
            auto& pool = whir::cuda::GpuPool::instance(); //拿到GPU资源池
            //上传root
            pool.upload_roots(reinterpret_cast<const uint64_t*>(base_roots.data()), base_roots.size());

            //准备3个compact输入数组
            //compact0: 所有 Ext3 元素的 c0
            //compact1: 所有 Ext3 元素的 c1
            //compact2: 所有 Ext3 元素的 c2
            std::vector<whir::algebra::Goldilocks> compact0;
            std::vector<whir::algebra::Goldilocks> compact1;
            std::vector<whir::algebra::Goldilocks> compact2;

            //提前分配容量
            compact0.reserve(coeffs.size() * poly_size);
            compact1.reserve(coeffs.size() * poly_size);
            compact2.reserve(coeffs.size() * poly_size);

            //把GoldilocksExt3拆分成三个Goldilocks数组
            for (const auto& poly : coeffs) {
                for (const auto& x : poly) {
                    compact0.push_back(x.c0());
                    compact1.push_back(x.c1());
                    compact2.push_back(x.c2());
                }
            }


            //准备三个输出数组
            //out0: c0 编码后的结果
            //out1: c1 编码后的结果
            //out2: c2 编码后的结果
            std::vector<whir::algebra::Goldilocks> out0(total_size);
            std::vector<whir::algebra::Goldilocks> out1(total_size);
            std::vector<whir::algebra::Goldilocks> out2(total_size);

            //分别调用三次GPU RS encode
            whir::cuda::gpu_interleaved_rs_encode(
                reinterpret_cast<const uint64_t*>(compact0.data()),
                reinterpret_cast<uint64_t*>(out0.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);
            whir::cuda::gpu_interleaved_rs_encode(
                reinterpret_cast<const uint64_t*>(compact1.data()),
                reinterpret_cast<uint64_t*>(out1.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);
            whir::cuda::gpu_interleaved_rs_encode(
                reinterpret_cast<const uint64_t*>(compact2.data()),
                reinterpret_cast<uint64_t*>(out2.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);

            //重新组合生成GolilocksExt3
            out.resize(total_size);
            for (std::size_t i = 0; i < total_size; ++i) {
                out[i] = F{out0[i], out1[i], out2[i]};
            }
            return true;
        }
        else if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt2>) {
            if (coeffs.empty()) {
                out.clear();
                return true;
            }
            const std::size_t poly_size = coeffs[0].size();
            const std::size_t total_size = coeffs.size() * interleaving_depth * codeword_length;
            if (!whir::cuda::gpu_dispatch_enabled() ||
                total_size < whir::cuda::gpu_ntt_threshold()) {
                if (whir::profile::cuda_trace_enabled()) {
                    std::fprintf(stderr,
                        "[CUDA RS Ext2] CPU fallback: num_polys=%zu poly_size=%zu codeword_length=%zu interleaving_depth=%zu total_elements=%zu threshold=%zu enabled=%d\n",
                        coeffs.size(), poly_size, codeword_length, interleaving_depth,
                        total_size, whir::cuda::gpu_ntt_threshold(),
                        whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
                }
                return false;
            }

            if (whir::profile::cuda_trace_enabled()) {
                std::fprintf(stderr,
                    "[CUDA RS Ext2] using GPU fast path via 2 Goldilocks component NTTs: num_polys=%zu poly_size=%zu codeword_length=%zu interleaving_depth=%zu total_elements=%zu\n",
                    coeffs.size(), poly_size, codeword_length, interleaving_depth, total_size);
            }

            ensure_roots_table(codeword_length);
            std::vector<whir::algebra::Goldilocks> base_roots;
            base_roots.reserve(roots_.size());
            for (const auto& root : roots_) {
                base_roots.push_back(root.c0());
            }

            auto& pool = whir::cuda::GpuPool::instance();
            pool.upload_roots(reinterpret_cast<const uint64_t*>(base_roots.data()), base_roots.size());

            std::vector<whir::algebra::Goldilocks> compact0;
            std::vector<whir::algebra::Goldilocks> compact1;
            compact0.reserve(coeffs.size() * poly_size);
            compact1.reserve(coeffs.size() * poly_size);
            for (const auto& poly : coeffs) {
                for (const auto& x : poly) {
                    compact0.push_back(x.c0());
                    compact1.push_back(x.c1());
                }
            }

            std::vector<whir::algebra::Goldilocks> out0(total_size);
            std::vector<whir::algebra::Goldilocks> out1(total_size);
            whir::cuda::gpu_interleaved_rs_encode(
                reinterpret_cast<const uint64_t*>(compact0.data()),
                reinterpret_cast<uint64_t*>(out0.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);
            whir::cuda::gpu_interleaved_rs_encode(
                reinterpret_cast<const uint64_t*>(compact1.data()),
                reinterpret_cast<uint64_t*>(out1.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);

            out.resize(total_size);
            for (std::size_t i = 0; i < total_size; ++i) {
                out[i] = F{out0[i], out1[i]};
            }
            return true;
        }
        else {
            whir::profile::cuda_trace("[CUDA RS] CPU fallback: GPU fast path only supports Goldilocks/GoldilocksExt2/GoldilocksExt3");
        }
#else
        (void)coeffs;
        (void)codeword_length;
        (void)interleaving_depth;
        (void)out;
#endif
        return false;
    }

    // 尝试在 GPU 上执行 RS 编码并直接返回 Goldilocks 小端字节。
    bool try_gpu_interleaved_rs_encode_blake3_matrix_leaves(
        std::span<const std::span<const F>> coeffs,
        std::size_t codeword_length,
        std::size_t interleaving_depth,
        std::vector<F>& out_matrix,
        std::vector<::whir::hash::Hash>& out_leaves
    ) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        if constexpr (std::is_same_v<F, whir::algebra::Goldilocks>) { //commit
            if (coeffs.empty()) {
                out_matrix.clear();
                out_leaves.clear();
                return true;
            }
            const std::size_t poly_size = coeffs[0].size();
            const std::size_t rows = coeffs.size() * interleaving_depth;
            const std::size_t total_size = rows * codeword_length;
            const std::size_t message_size = rows * sizeof(uint64_t);
            if (!whir::cuda::gpu_dispatch_enabled() ||
                total_size < whir::cuda::gpu_ntt_threshold() ||
                message_size == 0 ||
                (message_size % 64) != 0 ||
                message_size > 1024) {
                if (::whir::profile::cuda_trace_enabled()) {
                    std::fprintf(stderr,
                        "[CUDA] fused_blake3_leaves fallback field=Goldilocks rows=%zu total_size=%zu message_size=%zu threshold=%zu dispatch=%d\n",
                        rows, total_size, message_size, whir::cuda::gpu_ntt_threshold(),
                        whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
                }
                return false;
            }

            //GPU侧确认roots table，判断GPU pool里有没有可复用的roots,必要时CPU->GPU上传roots
            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_roots_prepare");
                ensure_roots_table(codeword_length);
                auto& pool = whir::cuda::GpuPool::instance();
                if (pool.roots_len() != roots_.size() ||
                    pool.roots_host() != reinterpret_cast<const uint64_t*>(roots_.data())) {
                    pool.upload_roots(reinterpret_cast<const uint64_t*>(roots_.data()), roots_.size());
                }
            }

            std::vector<F> compact; //在CPU上把输入的多个vectors拼成一个连续的一维数组，方便后面一次性拷贝到GPU
            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_compact");
                compact.reserve(coeffs.size() * poly_size);
                for (const auto& poly : coeffs) compact.insert(compact.end(), poly.begin(), poly.end());
            }

            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_resize_outputs");
                out_matrix.resize(total_size);
                out_leaves.resize(codeword_length);
            }
            return whir::cuda::gpu_interleaved_rs_encode_blake3_matrix_leaves( //跳到gpu_interleaved_encode_blake3_matrix_leaves函数
                reinterpret_cast<const uint64_t*>(compact.data()),
                reinterpret_cast<uint64_t*>(out_matrix.data()),
                reinterpret_cast<uint8_t*>(out_leaves.data()),
                coeffs.size(), poly_size, codeword_length, interleaving_depth);
        }
        else if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt2> ||  //prove阶段
                           std::is_same_v<F, whir::algebra::GoldilocksExt3>) {
            if (coeffs.empty()) {
                out_matrix.clear();
                out_leaves.clear();
                return true;
            }

            const std::size_t rows = coeffs.size() * interleaving_depth;
            const std::size_t poly_size = coeffs[0].size();
            const std::size_t total_size = rows * codeword_length;
            constexpr std::size_t element_bytes =
                std::is_same_v<F, whir::algebra::GoldilocksExt2> ? 16 : 24;
            const std::size_t message_size = rows * element_bytes;
            if (!whir::cuda::gpu_dispatch_enabled() ||
                total_size < whir::cuda::gpu_ntt_threshold() ||
                message_size == 0 ||
                (message_size % 64) != 0 ||
                message_size > 1024) {
                if (::whir::profile::cuda_trace_enabled()) { //如果开启了--cuda-trace
                    std::fprintf(stderr,
                        "[CUDA] fused_blake3_leaves fallback field=%s rows=%zu total_size=%zu message_size=%zu threshold=%zu dispatch=%d\n",
                        std::is_same_v<F, whir::algebra::GoldilocksExt2> ? "GoldilocksExt2" : "GoldilocksExt3",
                        rows, total_size, message_size, whir::cuda::gpu_ntt_threshold(),
                        whir::cuda::gpu_dispatch_enabled() ? 1 : 0);
                }
                return false;
            }

            std::vector<whir::algebra::Goldilocks> base_roots;
            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_roots_prepare");
                ensure_roots_table(codeword_length);
                base_roots.reserve(roots_.size());
                for (const auto& root : roots_) {
                    base_roots.push_back(root.c0());
                }
                auto& pool = whir::cuda::GpuPool::instance();
                pool.upload_roots(reinterpret_cast<const uint64_t*>(base_roots.data()), base_roots.size());
            }

            std::vector<whir::algebra::Goldilocks> compact0;
            std::vector<whir::algebra::Goldilocks> compact1;
            std::vector<whir::algebra::Goldilocks> compact2;
            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_compact");
                compact0.reserve(coeffs.size() * poly_size);
                compact1.reserve(coeffs.size() * poly_size);
                if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt3>) {
                    compact2.reserve(coeffs.size() * poly_size);
                }
                for (const auto& poly : coeffs) {
                    for (const auto& x : poly) {
                        compact0.push_back(x.c0());
                        compact1.push_back(x.c1());
                        if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt3>) {
                            compact2.push_back(x.c2());
                        }
                    }
                }
            }

            std::vector<whir::algebra::Goldilocks> out0;
            std::vector<whir::algebra::Goldilocks> out1;
            std::vector<whir::algebra::Goldilocks> out2;
            out0.resize(total_size);
            out1.resize(total_size);
            if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt3>) {
                out2.resize(total_size);
            }

            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_resize_outputs");
                out_leaves.resize(codeword_length);
            }
            bool gpu_ok = false;
            //GoldilocksExt2域
            //进入ext2_matrix_leaves函数
            if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt2>) {
                gpu_ok = whir::cuda::gpu_interleaved_rs_encode_blake3_ext2_matrix_leaves(
                    reinterpret_cast<const uint64_t*>(compact0.data()),
                    reinterpret_cast<const uint64_t*>(compact1.data()),
                    reinterpret_cast<uint64_t*>(out0.data()),
                    reinterpret_cast<uint64_t*>(out1.data()),
                    reinterpret_cast<uint8_t*>(out_leaves.data()),
                    coeffs.size(), poly_size, codeword_length, interleaving_depth);
            } else {
                //GoldilocksExt3域
                //进入ext3_matrix_leaves函数
                gpu_ok = whir::cuda::gpu_interleaved_rs_encode_blake3_ext3_matrix_leaves(
                    reinterpret_cast<const uint64_t*>(compact0.data()),
                    reinterpret_cast<const uint64_t*>(compact1.data()),
                    reinterpret_cast<const uint64_t*>(compact2.data()),
                    reinterpret_cast<uint64_t*>(out0.data()),
                    reinterpret_cast<uint64_t*>(out1.data()),
                    reinterpret_cast<uint64_t*>(out2.data()),
                    reinterpret_cast<uint8_t*>(out_leaves.data()),
                    coeffs.size(), poly_size, codeword_length, interleaving_depth);
            }
            if (!gpu_ok) {
                out_leaves.clear();
                return false;
            }

            {
                ::whir::profile::ScopedTimer timer("cuda", total_size, "witness_resize_outputs");
                out_matrix.resize(total_size);
                for (std::size_t i = 0; i < total_size; ++i) {
                    if constexpr (std::is_same_v<F, whir::algebra::GoldilocksExt2>) {
                        out_matrix[i] = F{out0[i], out1[i]};
                    } else {
                        out_matrix[i] = F{out0[i], out1[i], out2[i]};
                    }
                }
            }
            return true;
        }
#else
        (void)coeffs;
        (void)codeword_length;
        (void)interleaving_depth;
        (void)out_matrix;
        (void)out_leaves;
#endif
        return false;
    }

    // 不含 1/N 缩放因子的逆 NTT。
    //
    // INTT 定义（不含 1/N）：
    //   a_j = Σ_{k=0}^{N-1} A_k · ω^(-j·k)
    //
    // 实现：翻转 [1..N-1] 后执行正向 NTT。调用方需自行除以 N。
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

    // 批量逆 NTT（不含 1/N 缩放）。每个 size 元素块独立变换。
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

    // 惰性保证根表至少包含 order 个元素。
    // 首次调用：构建 [ω^0, ω^1, ..., ω^(order-1)]。
    // 后续调用：若当前大小不可被 order 整除，通过 lcm 扩展并用新生成元重建整张表。
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

    // 递归 √N Cooley-Tukey 分解步骤。
    //
    // 将 size 分解为 n1 × n2，其中 n1 = sqrt_factor(size)：
    //   1. 转置 n1 × n2 → n2 × n1
    //   2. 对每行执行 NTT(n1)
    //   3. 转置 n2 × n1 → n1 × n2
    //   4. 乘以 twiddle 因子
    //   5. 对每行执行 NTT(n2)
    //   6. 转置 n1 × n2 → n2 × n1
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

    // 根据规模分派至最优 NTT 实现。
    //
    // 规模路由：
    //   0, 1  — 恒等变换（无操作）
    //   2     — 单蝶形：a' = a+b, b' = a-b
    //   3     — Rader 算法（归约至规模 2 的 NTT）
    //   4     — 两层 Cooley-Tukey 蝶形
    //   8     — 三层蝶形（含 twiddle 因子）
    //   16    — 4×4 复合 NTT（列 NTT → twiddle → 行 NTT → 转置）
    //   其他  — ntt_recurse（√N 递归分解）
    //
    // 前置条件：values.size() % size == 0，roots.size() % size == 0。
    void ntt_power_of_two(std::span<F> values, std::span<const F> roots, std::size_t size) {
        assert(is_power_of_two(size));
        assert(values.size() % size == 0);
        assert(roots.size() % size == 0);
        for (std::size_t off = 0; off + size <= values.size(); off += size) {
            ntt_power_of_two(std::span<F>{values.data() + off, size}, roots);
        }
    }

    void ntt_power_of_two(std::span<F> values, std::span<const F> roots) {
        const std::size_t n = values.size();
        assert(is_power_of_two(n));
        if (n <= 1) return;

        // DIT radix-2 NTT: bit-reverse first so the final values stay in natural order.
        for (std::size_t i = 1, j = 0; i < n; ++i) {
            std::size_t bit = n >> 1;
            for (; (j & bit) != 0; bit >>= 1) {
                j ^= bit;
            }
            j ^= bit;
            if (i < j) {
                std::swap(values[i], values[j]);
            }
        }

        const std::size_t root_stride = roots.size() / n;
        for (std::size_t len = 2; len <= n; len <<= 1) {
            const std::size_t step = root_stride * (n / len);
            for (std::size_t i = 0; i < n; i += len) {
                std::size_t root_index = 0;
                const std::size_t half = len >> 1;
                for (std::size_t j = 0; j < half; ++j) {
                    const F u = values[i + j];
                    const F v = mul_by_root(values[i + j + half], roots[root_index]);
                    values[i + j] = u + v;
                    values[i + j + half] = u - v;
                    root_index += step;
                }
            }
        }
    }

    void ntt_dispatch(std::span<F> values, std::span<const F> roots, std::size_t size) {
        assert(values.size() % size == 0);
        assert(roots.size() % size == 0);
        switch (size) {
            case 0:
            case 1:
                return;
            case 2: {
                for (std::size_t off = 0; off + 2 <= values.size(); off += 2) {
                    F a = values[off + 0];
                    F b = values[off + 1];
                    values[off + 0] = a + b;
                    values[off + 1] = a - b;
                }
                return;
            }
            case 3: {
                // Rader 算法：将规模 3 的循环卷积映射为规模 2 的 NTT
                for (std::size_t off = 0; off + 3 <= values.size(); off += 3) {
                    F* v = values.data() + off;
                    const F v0 = v[0];
                    F t1 = v[1] + v[2];
                    F t2 = v[1] - v[2];
                    v[1] = t1;
                    v[2] = t2;
                    v[0] = v[0] + v[1];
                    v[1] = mul_by_root(v[1], half_omega_3_1_plus_2);
                    v[2] = mul_by_root(v[2], half_omega_3_1_min_2);
                    v[1] = v[1] + v0;
                    F u1 = v[1] + v[2];
                    F u2 = v[1] - v[2];
                    v[1] = u1;
                    v[2] = u2;
                }
                return;
            }
            case 4: {
                // 两层蝶形：奇偶分裂后乘以 ω_4
                for (std::size_t off = 0; off + 4 <= values.size(); off += 4) {
                    F* v = values.data() + off;
                    F a02p = v[0] + v[2], a02m = v[0] - v[2];
                    F a13p = v[1] + v[3], a13m = v[1] - v[3];
                    v[0] = a02p; v[2] = a02m;
                    v[1] = a13p; v[3] = a13m;
                    v[3] = mul_by_root(v[3], omega_4_1);
                    F b01p = v[0] + v[1], b01m = v[0] - v[1];
                    F b23p = v[2] + v[3], b23m = v[2] - v[3];
                    v[0] = b01p; v[1] = b01m;
                    v[2] = b23p; v[3] = b23m;
                    std::swap(v[1], v[2]);
                }
                return;
            }
            case 8: {
                // 三层蝶形：使用 ω_8^{1,3} 和 ω_4 作为 twiddle 因子。
                // 末尾位反转：swap(1,4), swap(3,6)。
                for (std::size_t off = 0; off + 8 <= values.size(); off += 8) {
                    F* v = values.data() + off;
                    {
                        F a0 = v[0] + v[4], a4 = v[0] - v[4]; v[0]=a0; v[4]=a4;
                        F a1 = v[1] + v[5], a5 = v[1] - v[5]; v[1]=a1; v[5]=a5;
                        F a2 = v[2] + v[6], a6 = v[2] - v[6]; v[2]=a2; v[6]=a6;
                        F a3 = v[3] + v[7], a7 = v[3] - v[7]; v[3]=a3; v[7]=a7;
                    }
                    v[5] = mul_by_root(v[5], omega_8_1);
                    v[6] = mul_by_root(v[6], omega_4_1);
                    v[7] = mul_by_root(v[7], omega_8_3);
                    {
                        F a0 = v[0] + v[2], a2 = v[0] - v[2]; v[0]=a0; v[2]=a2;
                        F a1 = v[1] + v[3], a3 = v[1] - v[3]; v[1]=a1; v[3]=a3;
                    }
                    v[3] = mul_by_root(v[3], omega_4_1);
                    {
                        F a0 = v[0] + v[1], a1 = v[0] - v[1]; v[0]=a0; v[1]=a1;
                        F a2 = v[2] + v[3], a3 = v[2] - v[3]; v[2]=a2; v[3]=a3;
                        F a4 = v[4] + v[6], a6 = v[4] - v[6]; v[4]=a4; v[6]=a6;
                        F a5 = v[5] + v[7], a7 = v[5] - v[7]; v[5]=a5; v[7]=a7;
                    }
                    v[7] = mul_by_root(v[7], omega_4_1);
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
                // 4×4 复合 NTT：列 NTT → twiddle → 行 NTT → 转置
                for (std::size_t off = 0; off + 16 <= values.size(); off += 16) {
                    F* base = values.data() + off;
                    // 列 NTT（4 列，步长 4）
                    for (std::size_t i = 0; i < 4; ++i) {
                        F* v = base + i;
                        F t0p = v[0] + v[8], t0m = v[0] - v[8]; v[0]=t0p; v[8]=t0m;
                        F t4p = v[4] + v[12], t4m = v[4] - v[12]; v[4]=t4p; v[12]=t4m;
                        v[12] = mul_by_root(v[12], omega_4_1);
                        F u0p = v[0] + v[4], u0m = v[0] - v[4]; v[0]=u0p; v[4]=u0m;
                        F u8p = v[8] + v[12], u8m = v[8] - v[12]; v[8]=u8p; v[12]=u8m;
                        std::swap(v[4], v[8]);
                    }
                    // twiddle 乘法（ω_16 的各次幂）
                    base[5]  = mul_by_root(base[5], omega_16_1);
                    base[6]  = mul_by_root(base[6], omega_8_1);
                    base[7]  = mul_by_root(base[7], omega_16_3);
                    base[9]  = mul_by_root(base[9], omega_8_1);
                    base[10] = mul_by_root(base[10], omega_4_1);
                    base[11] = mul_by_root(base[11], omega_8_3);
                    base[13] = mul_by_root(base[13], omega_16_3);
                    base[14] = mul_by_root(base[14], omega_8_3);
                    base[15] = mul_by_root(base[15], omega_16_9);
                    // 行 NTT（4 行，连续 4 元素块）
                    for (std::size_t i = 0; i < 4; ++i) {
                        F* v = base + i * 4;
                        F a02p = v[0] + v[2], a02m = v[0] - v[2];
                        F a13p = v[1] + v[3], a13m = v[1] - v[3];
                        v[0]=a02p; v[2]=a02m;
                        v[1]=a13p; v[3]=a13m;
                        v[3] = mul_by_root(v[3], omega_4_1);
                        F b01p = v[0] + v[1], b01m = v[0] - v[1];
                        F b23p = v[2] + v[3], b23m = v[2] - v[3];
                        v[0]=b01p; v[1]=b01m;
                        v[2]=b23p; v[3]=b23m;
                        std::swap(v[1], v[2]);
                    }
                    // 4×4 转置（固定交换模式）
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
                ntt_recurse(values, roots, size);
                return;
        }
    }

    // ---- 数据成员 ----

    std::size_t order_ = 0;
    F omega_order_ = F::zero();

    // 小规模展开路径的预计算根常量
    F half_omega_3_1_plus_2 = F::zero();  // (ω_3 + ω_3^2) / 2
    F half_omega_3_1_min_2 = F::zero();   // (ω_3 - ω_3^2) / 2
    F omega_4_1 = F::zero();              // ω_4^1
    F omega_8_1 = F::zero();              // ω_8^1
    F omega_8_3 = F::zero();              // ω_8^3
    F omega_16_1 = F::zero();             // ω_16^1
    F omega_16_3 = F::zero();             // ω_16^3
    F omega_16_9 = F::zero();             // ω_16^9

    // 根表：[ω^0, ω^1, ..., ω^(size-1)]，惰性初始化并通过 lcm 按需扩展。
    std::vector<F> roots_;
};

// Rust 中的全局自由函数（ntt, intt, ntt_batch 等）在 C++ 中不作为全局函数提供；
// 调用方直接持有 NttEngine<F> 实例。
// Goldilocks 域的单例引擎见 cooley_tukey_goldilocks.hpp。

} // namespace whir::algebra::ntt
