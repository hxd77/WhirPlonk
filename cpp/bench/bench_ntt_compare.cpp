// ===========================================================================
// bench_ntt_compare.cpp — CPU vs GPU NTT 性能对比基准测试
//
// 功能:
//   对同一组 Goldilocks 域元素分别执行 CPU NTT 和 GPU NTT，
//   记录两者的耗时，并验证结果一致性（正确性检查）。
//   输出 CSV 格式，便于导入 Excel/Python 绘图分析。
//
// 输入:
//   命令行参数（均可选）:
//     --runs <N>              每个尺寸重复运行次数，取最优值（默认 3）
//     --sizes <n1> <n2> ...   自定义 NTT 长度列表（默认 1024/4096/65536/1048576/16777216）
//
// 输出:
//   CSV 格式到 stdout，每行对应一个 NTT 尺寸:
//     input_size             — NTT 长度（元素个数）
//     cpu_ms                 — CPU NTT 耗时（毫秒）
//     gpu_h2d_ms             — GPU Host→Device 数据传输耗时
//     gpu_kernel_ms          — GPU 内核计算耗时
//     gpu_d2h_ms             — GPU Device→Host 数据回传耗时
//     gpu_total_ms           — GPU 端到端总耗时（传输+计算+回传）
//     speedup_kernel_only    — 加速比 = cpu_ms / gpu_kernel_ms（仅计算）
//     speedup_end_to_end     — 加速比 = cpu_ms / gpu_total_ms（含传输）
//     correctness            — PASS（CPU/GPU 结果一致）/ FAIL / GPU_UNAVAILABLE
//
// 用法示例:
//   bench_ntt_compare.exe                          # 默认尺寸，运行 3 次
//   bench_ntt_compare.exe --runs 5                 # 运行 5 次取最优
//   bench_ntt_compare.exe --sizes 1024 65536       # 仅测试 1K 和 64K
//   bench_ntt_compare.exe --sizes 1048576 --runs 1 # 单次 1M NTT
//
// 输出示例:
//   input_size,cpu_ms,gpu_h2d_ms,gpu_kernel_ms,gpu_d2h_ms,gpu_total_ms,speedup_kernel_only,speedup_end_to_end,correctness
//   1024,0.012345,0.001234,0.003456,0.001234,0.005924,3.571,2.084,PASS
//   4096,0.045678,0.002345,0.008765,0.002345,0.013455,5.210,3.395,PASS
//   ...
//
// 编译:
//   CPU-only: cmake -S cpp -B cpp/build && cmake --build cpp/build --target bench_ntt_compare
//   CUDA:     cmake -S cpp -B cpp/build_cuda -DWHIR_CUDA=ON && cmake --build cpp/build_cuda --target bench_ntt_compare
//
// 说明:
//   - 未启用 CUDA 时，GPU 列输出 0，correctness 列显示 GPU_UNAVAILABLE
//   - 使用确定性 LCG 随机数生成输入，保证每次运行结果可复现
//   - CPU 运行时会临时禁用 GPU dispatch，确保走纯 CPU 路径
//   - GPU 运行时会临时将阈值设为 0，强制所有 NTT 走 GPU 路径
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <span>
#include <string>
#include <vector>

using whir::algebra::Goldilocks;

// ---- 确定性伪随机数生成器 ----
// 使用 LCG（线性同余生成器），种子固定，保证跨平台可复现。
// 与 Rust 端的 deterministic_rng 对应。
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

// ---- 计时结果 ----
struct CpuTiming {
    double ms = 0.0;  // CPU NTT 总耗时（毫秒）
};

struct GpuTimingRow {
    double malloc_ms = 0.0;   // cudaMalloc/cudaFree 热路径分配耗时
    double h2d_ms = 0.0;      // Host → Device 传输耗时
    double kernel_ms = 0.0;   // GPU 内核计算耗时
    double d2h_ms = 0.0;      // Device → Host 回传耗时
    double total_ms = 0.0;    // 端到端总耗时 = h2d + kernel + d2h
    bool available = false;   // GPU 是否可用（未启用 CUDA 时为 false）
};

// ---- 生成确定性输入数据 ----
// 使用 LCG 生成 n 个 Goldilocks 域元素。
// 种子与 n 异或，确保不同尺寸生成不同序列。
static std::vector<Goldilocks> make_input(std::size_t n) {
    Lcg rng(0x4e54545f434f4d50ULL ^ static_cast<uint64_t>(n));
    std::vector<Goldilocks> values(n);
    for (auto& v : values) v = Goldilocks::from_u64(rng.next());
    return values;
}

// ---- CPU NTT 运行 ----
// 在 CPU 上执行批量 NTT（就地变换）。
// 如果启用了 CUDA，临时禁用 GPU dispatch 以确保走纯 CPU 路径。
// 输入: values — 待变换的 Goldilocks 域元素向量（会被就地修改）
//       n      — 每个子 NTT 的长度（向量总长度必须是 n 的倍数）
// 返回: CpuTiming，包含 CPU 耗时
static CpuTiming run_cpu(std::vector<Goldilocks>& values, std::size_t n) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT) //同时定义这两个宏才会编译
    // 临时禁用 GPU，强制走 CPU 路径
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    whir::cuda::set_gpu_dispatch_enabled(false);
#endif
    const auto t0 = std::chrono::steady_clock::now(); //开始计时
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
    const auto t1 = std::chrono::steady_clock::now(); //结束计时
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT) 
    // 恢复原始 GPU 开关状态
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
    return {std::chrono::duration<double, std::milli>(t1 - t0).count()}; //返回时间
}

// ---- GPU NTT 运行 ----
// 在 GPU 上执行批量 NTT（就地变换）。
// 临时将 GPU 阈值设为 0，强制所有 NTT 走 GPU 路径。
// 输入: values — 待变换的 Goldilocks 域元素向量（会被就地修改）
//       n      — 每个子 NTT 的长度
// 返回: GpuTimingRow，包含各阶段耗时；未启用 CUDA 时 available=false
static GpuTimingRow run_gpu(std::vector<Goldilocks>& values, std::size_t n) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    // 强制启用 GPU 并将阈值设为 0，确保所有规模都走 GPU
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);
    whir::cuda::cuda_warmup();
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
    // 从 CUDA 集成层获取各阶段计时
    const auto timing = whir::cuda::last_ntt_timing();
    // 恢复原始配置
    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
    return {timing.malloc_ms, timing.h2d_ms, timing.kernel_ms, timing.d2h_ms,
            timing.total_ms + timing.malloc_ms, timing.used_gpu};
#else
    (void)values;
    (void)n;
    return {};  // 未启用 CUDA，返回空结果
#endif
}

int main(int argc, char** argv) {
    try {
        // ---- 默认测试尺寸 ----
        // 1K / 4K / 64K / 1M / 16M 元素，覆盖从小到大的典型场景
        std::vector<std::size_t> sizes = {
            std::size_t{1} << 10,   // 1024
            std::size_t{1} << 12,   // 4096
            std::size_t{1} << 16,   // 65536
            std::size_t{1} << 20,   // 1048576 (1M)
            std::size_t{1} << 24,   // 16777216 (16M)
        };
        int runs = 3;  // 每个尺寸重复运行次数，取最优值

        // ---- 解析命令行参数 ----
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--runs" && i + 1 < argc) {
                runs = std::atoi(argv[++i]);
            } else if (arg == "--sizes") {
                sizes.clear();
                while (i + 1 < argc && argv[i + 1][0] != '-') {
                    sizes.push_back(static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10)));
                }
            }
        }

        // ---- CSV 表头 ----
        std::printf("input_size,cpu_ms,gpu_malloc_ms,gpu_h2d_ms,gpu_kernel_ms,gpu_d2h_ms,gpu_total_ms,"
                    "speedup_kernel_only,speedup_end_to_end,correctness\n");

        // ---- 逐尺寸运行基准测试 ----
        for (std::size_t n : sizes) {
            double best_cpu = 1.0e300;    // 记录最优（最小）CPU 耗时
            GpuTimingRow best_gpu{};       // 记录最优（最小）GPU 耗时
            bool correct = true;           // CPU/GPU 结果是否一致

            for (int r = 0; r < std::max(runs, 1); ++r) {
                // 生成相同的输入数据，分别给 CPU 和 GPU
                auto cpu_values = make_input(n);
                auto gpu_values = cpu_values;  // 拷贝一份相同数据

                // 运行 CPU NTT
                const auto cpu = run_cpu(cpu_values, n);
                best_cpu = std::min(best_cpu, cpu.ms);

                // 运行 GPU NTT
                const auto gpu = run_gpu(gpu_values, n);
                if (gpu.available &&
                    (!best_gpu.available || gpu.total_ms < best_gpu.total_ms)) {
                    best_gpu = gpu;
                }

                // 正确性检查: CPU 和 GPU 的输出必须逐元素一致
                // 两者使用相同的输入和相同的 NTT 算法，结果应完全相同
                if (gpu.available && cpu_values != gpu_values) {
                    correct = false;
                }
            }

            // 计算加速比
            // kernel_only: 仅比较计算部分（不含数据传输），反映 GPU 计算能力
            // end_to_end:  含传输的完整耗时，反映实际使用场景的收益
            const double kernel_speedup =
                best_gpu.available && best_gpu.kernel_ms > 0.0 ? best_cpu / best_gpu.kernel_ms : 0.0;
            const double e2e_speedup =
                best_gpu.available && best_gpu.total_ms > 0.0 ? best_cpu / best_gpu.total_ms : 0.0;

            // 输出一行 CSV
            std::printf("%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f,%s\n",
                        n, best_cpu, best_gpu.malloc_ms, best_gpu.h2d_ms, best_gpu.kernel_ms,
                        best_gpu.d2h_ms, best_gpu.total_ms,
                        kernel_speedup, e2e_speedup,
                        best_gpu.available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_ntt_compare error: %s\n", e.what());
        return 2;
    }
}
