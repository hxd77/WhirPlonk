#pragma once

/**
 * @file profiling.hpp
 * @brief 性能分析工具库
 *
 * 提供 CSV 格式的性能数据输出和 CUDA 操作跟踪功能。
 * 通过环境变量控制启用/禁用，支持运行时动态配置。
 *
 * 环境变量：
 *   WHIR_PROFILE=1     启用 CSV 性能数据输出到 stderr
 *   WHIR_CUDA_TRACE=1  启用 CUDA 操作详细跟踪
 *
 * 使用示例：
 *   // 基本用法 - 记录单次操作
 *   auto start = whir::profile::Clock::now();
 *   // ... 执行操作 ...
 *   whir::profile::record("ntt", 1048576, "cpu_kernel", whir::profile::ms_since(start));
 *
 *   // RAII 用法 - 自动记录代码块执行时间
 *   {
 *       whir::profile::ScopedTimer timer("rs_encode", 65536, "gpu_total");
 *       // ... 执行 GPU RS 编码 ...
 *   } // 析构时自动记录时间
 *
 *   // CUDA 跟踪
 *   whir::profile::cuda_trace("Starting GPU NTT kernel");
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace whir::profile {

using Clock = std::chrono::steady_clock;

/**
 * @brief 检查环境变量是否启用
 *
 * 支持多种启用表示：非空、非 '0'、非 'f/F'、非 'n/N'
 *
 * @param name 环境变量名
 * @return true 如果环境变量存在且表示启用
 * @return false 如果环境变量不存在或表示禁用
 *
 * 示例：
 *   env_enabled("WHIR_PROFILE")  // 检查是否启用性能分析
 *   env_enabled("WHIR_CUDA_TRACE")  // 检查是否启用 CUDA 跟踪
 */
inline bool env_enabled(const char* name) {
    const char* v = std::getenv(name);
    return v != nullptr && v[0] != '\0' && v[0] != '0'
        && v[0] != 'f' && v[0] != 'F' && v[0] != 'n' && v[0] != 'N';
}

/**
 * @brief 获取 CSV 输出启用标志的引用
 *
 * 首次调用时从 WHIR_PROFILE 环境变量初始化。
 * 可通过 set_csv_enabled() 动态修改。
 *
 * @return bool& CSV 输出启用标志的引用
 */
inline bool& csv_enabled_flag() {
    static bool enabled = env_enabled("WHIR_PROFILE");
    return enabled;
}

/**
 * @brief 获取 CUDA 跟踪启用标志的引用
 *
 * 首次调用时从 WHIR_CUDA_TRACE 环境变量初始化。
 * 可通过 set_cuda_trace_enabled() 动态修改。
 *
 * @return bool& CUDA 跟踪启用标志的引用
 */
inline bool& cuda_trace_enabled_flag() {
    static bool enabled = env_enabled("WHIR_CUDA_TRACE");
    return enabled;
}

/**
 * @brief 设置 CSV 输出启用状态
 *
 * @param enabled true 启用 CSV 输出，false 禁用
 *
 * 示例：
 *   whir::profile::set_csv_enabled(true);  // 启用 CSV 输出
 *   whir::profile::set_csv_enabled(false); // 禁用 CSV 输出
 */
inline void set_csv_enabled(bool enabled) {
    csv_enabled_flag() = enabled;
}

/**
 * @brief 检查 CSV 输出是否启用
 *
 * @return true 如果 CSV 输出启用
 * @return false 如果 CSV 输出禁用
 */
inline bool csv_enabled() {
    return csv_enabled_flag();
}

/**
 * @brief 设置 CUDA 跟踪启用状态
 *
 * @param enabled true 启用 CUDA 跟踪，false 禁用
 *
 * 示例：
 *   whir::profile::set_cuda_trace_enabled(true);  // 启用 CUDA 跟踪
 */
inline void set_cuda_trace_enabled(bool enabled) {
    cuda_trace_enabled_flag() = enabled;
}

/**
 * @brief 检查 CUDA 跟踪是否启用
 *
 * @return true 如果 CUDA 跟踪启用
 * @return false 如果 CUDA 跟踪禁用
 */
inline bool cuda_trace_enabled() {
    return cuda_trace_enabled_flag();
}

/**
 * @brief 打印 CSV 表头（仅打印一次）
 *
 * 首次调用时输出 CSV 格式表头到 stderr：
 * mode,size,stage,time_ms
 *
 * 后续调用不会重复输出。
 */
inline void print_csv_header_once() {
    static bool printed = false;
    if (!printed) {
        std::fprintf(stderr, "mode,size,stage,time_ms\n");
        printed = true;
    }
}

/**
 * @brief 记录性能数据点到 CSV 输出
 *
 * 当 CSV 输出启用时，将性能数据以 CSV 格式输出到 stderr。
 * 输出格式：mode,size,stage,time_ms
 *
 * @param mode 操作模式/类型（如 "ntt", "rs_encode", "merkle"）
 * @param size 数据规模（如元素数量、多项式大小）
 * @param stage 操作阶段（如 "cpu_kernel", "gpu_total", "h2d", "d2h"）
 * @param time_ms 耗时（毫秒）
 *
 * 示例：
 *   // 记录 NTT 内核执行时间
 *   whir::profile::record("ntt", 1048576, "cpu_kernel", 12.345);
 *
 *   // 记录 RS 编码总时间
 *   whir::profile::record("rs_encode", 65536, "gpu_total", 45.678);
 *
 *   // 记录数据传输时间
 *   whir::profile::record("transfer", 1048576, "h2d", 1.234);
 *
 * 输出示例（stderr）：
 *   mode,size,stage,time_ms
 *   ntt,1048576,cpu_kernel,12.345000
 *   rs_encode,65536,gpu_total,45.678000
 *   transfer,1048576,h2d,1.234000
 */
inline void record(std::string_view mode, std::size_t size, std::string_view stage, double time_ms) {
    if (!csv_enabled()) return;
    print_csv_header_once();
    std::fprintf(stderr, "%.*s,%zu,%.*s,%.6f\n",
        static_cast<int>(mode.size()), mode.data(),
        size,
        static_cast<int>(stage.size()), stage.data(),
        time_ms);
}

/**
 * @brief 计算从起始时间点到现在的毫秒数
 *
 * 使用 steady_clock 计算时间差，适用于性能测量。
 *
 * @param start 起始时间点
 * @return double 从起始时间点到现在的毫秒数
 *
 * 示例：
 *   auto start = whir::profile::Clock::now();
 *   // ... 执行操作 ...
 *   double elapsed = whir::profile::ms_since(start);
 *   std::printf("操作耗时: %.3f ms\n", elapsed);
 */
inline double ms_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

/**
 * @brief RAII 风格的性能计时器
 *
 * 构造时记录起始时间，析构时自动计算并记录耗时。
 * 适用于测量代码块的执行时间。
 *
 * 构造参数：
 *   mode  - 操作模式/类型（如 "ntt", "rs_encode"）
 *   size  - 数据规模（如元素数量）
 *   stage - 操作阶段（如 "cpu_kernel", "gpu_total"）
 *
 * 使用示例：
 *   // 基本用法
 *   {
 *       whir::profile::ScopedTimer timer("ntt", 1048576, "cpu_total");
 *       // ... 执行 NTT 变换 ...
 *   } // 析构时自动记录时间
 *
 *   // 嵌套使用 - 测量不同阶段
 *   {
 *       whir::profile::ScopedTimer total_timer("rs_encode", 65536, "total");
 *
 *       {
 *           whir::profile::ScopedTimer ntt_timer("rs_encode", 65536, "ntt");
 *           // ... 执行 NTT ...
 *       } // 记录 NTT 阶段时间
 *
 *       {
 *           whir::profile::ScopedTimer transpose_timer("rs_encode", 65536, "transpose");
 *           // ... 执行转置 ...
 *       } // 记录转置阶段时间
 *   } // 记录总时间
 *
 * 输出示例（当 WHIR_PROFILE=1 时）：
 *   mode,size,stage,time_ms
 *   rs_encode,65536,ntt,12.345000
 *   rs_encode,65536,transpose,3.456000
 *   rs_encode,65536,total,15.801000
 */
class ScopedTimer {
public:
    /**
     * @brief 构造计时器
     *
     * @param mode 操作模式/类型
     * @param size 数据规模
     * @param stage 操作阶段
     */
    ScopedTimer(std::string_view mode, std::size_t size, std::string_view stage)
        : mode_(mode)
        , stage_(stage)
        , size_(size)
        , enabled_(csv_enabled())
        , start_(enabled_ ? Clock::now() : Clock::time_point{})
    {}

    /**
     * @brief 析构计时器，自动记录耗时
     */
    ~ScopedTimer() {
        if (!enabled_) return;
        record(mode_, size_, stage_, ms_since(start_));
    }

private:
    std::string_view mode_;      ///< 操作模式/类型
    std::string_view stage_;     ///< 操作阶段
    std::size_t size_;           ///< 数据规模
    bool enabled_;               ///< 是否启用本次计时
    Clock::time_point start_;    ///< 起始时间点
};

/**
 * @brief 输出 CUDA 跟踪信息到 stderr
 *
 * 当 CUDA 跟踪启用时，输出调试信息到 stderr。
 * 用于跟踪 CUDA 操作的执行流程。
 *
 * @param message 跟踪信息
 *
 * 示例：
 *   whir::profile::cuda_trace("Starting GPU NTT kernel launch");
 *   whir::profile::cuda_trace("GPU memory allocation completed");
 *   whir::profile::cuda_trace("CUDA kernel execution finished");
 *
 * 输出示例（当 WHIR_CUDA_TRACE=1 时）：
 *   Starting GPU NTT kernel launch
 *   GPU memory allocation completed
 *   CUDA kernel execution finished
 */
inline void cuda_trace(std::string_view message) {
    if (cuda_trace_enabled()) {
        std::fprintf(stderr, "%.*s\n", static_cast<int>(message.size()), message.data());
    }
}

} // namespace whir::profile
