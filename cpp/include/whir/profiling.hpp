#pragma once

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace whir::profile {

using Clock = std::chrono::steady_clock;

inline bool env_enabled(const char* name) {
    const char* v = std::getenv(name);
    return v != nullptr && v[0] != '\0' && v[0] != '0'
        && v[0] != 'f' && v[0] != 'F' && v[0] != 'n' && v[0] != 'N';
}

inline bool& csv_enabled_flag() {
    static bool enabled = env_enabled("WHIR_PROFILE");
    return enabled;
}

inline bool& cuda_trace_enabled_flag() {
    static bool enabled = env_enabled("WHIR_CUDA_TRACE");
    return enabled;
}

inline void set_csv_enabled(bool enabled) {
    csv_enabled_flag() = enabled;
}

inline bool csv_enabled() {
    return csv_enabled_flag();
}

inline void set_cuda_trace_enabled(bool enabled) {
    cuda_trace_enabled_flag() = enabled;
}

inline bool cuda_trace_enabled() {
    return cuda_trace_enabled_flag();
}

inline std::string_view& current_phase_ref() {
    static std::string_view phase = "none";
    return phase;
}

inline std::string_view current_phase() {
    return current_phase_ref();
}

inline void print_csv_header_once() {
    static bool printed = false;
    if (!printed) {
        std::fprintf(stderr, "mode,phase,size,stage,time_ms\n");
        printed = true;
    }
}

inline bool keep_stage(std::string_view stage) {
    return stage == "witness_encoding"
        || stage == "witness_compact"
        || stage == "witness_roots_prepare"
        || stage == "witness_h2d"
        || stage == "witness_gpu_alloc"
        || stage == "witness_rs_encode"
        || stage == "witness_leaf_hash"
        || stage == "witness_d2h"
        || stage == "witness_resize_outputs"
        || stage == "merkle_leaf_total"
        || stage == "merkle_build_total"
        || stage == "ood_evaluation"
        || stage == "commit_total"
        || stage == "prove_total"
        || stage == "total_prover";
}

//把一次性能计时结果按CSV格式打印到stderr
inline void record(std::string_view mode, std::size_t size, std::string_view stage, double time_ms) {
    if (!csv_enabled()) return;
    if (!keep_stage(stage)) return;
    print_csv_header_once();
    const auto phase = current_phase();
    std::fprintf(stderr, "%.*s,%.*s,%zu,%.*s,%.6f\n",
        static_cast<int>(mode.size()), mode.data(),
        static_cast<int>(phase.size()), phase.data(),
        size,
        static_cast<int>(stage.size()), stage.data(),
        time_ms);
}

inline double ms_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

class PhaseGuard {
public:
    explicit PhaseGuard(std::string_view phase)
        : previous_(current_phase())
    {
        current_phase_ref() = phase;
    }

    ~PhaseGuard() {
        current_phase_ref() = previous_;
    }

    PhaseGuard(const PhaseGuard&) = delete;
    PhaseGuard& operator=(const PhaseGuard&) = delete;

private:
    std::string_view previous_;
};

class ScopedTimer { //作用域计时器
public:
    //创建时开始计时
    ScopedTimer(std::string_view mode, std::size_t size, std::string_view stage)
        : mode_(mode)
        , stage_(stage)
        , size_(size)
        , start_(Clock::now())
    {}

    //调用析构函数时自动结束执行
    ~ScopedTimer() {
        record(mode_, size_, stage_, ms_since(start_));
    }

private:
    std::string_view mode_;
    std::string_view stage_;
    std::size_t size_;
    Clock::time_point start_;
};

inline void cuda_trace(std::string_view message) {
    if (cuda_trace_enabled()) {
        std::fprintf(stderr, "%.*s\n", static_cast<int>(message.size()), message.data());
    }
}

} // namespace whir::profile
