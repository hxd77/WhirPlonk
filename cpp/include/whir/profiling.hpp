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

inline void print_csv_header_once() {
    static bool printed = false;
    if (!printed) {
        std::fprintf(stderr, "mode,size,stage,time_ms\n");
        printed = true;
    }
}

inline void record(std::string_view mode, std::size_t size, std::string_view stage, double time_ms) {
    if (!csv_enabled()) return;
    print_csv_header_once();
    std::fprintf(stderr, "%.*s,%zu,%.*s,%.6f\n",
        static_cast<int>(mode.size()), mode.data(),
        size,
        static_cast<int>(stage.size()), stage.data(),
        time_ms);
}

inline double ms_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

class ScopedTimer {
public:
    ScopedTimer(std::string_view mode, std::size_t size, std::string_view stage)
        : mode_(mode)
        , stage_(stage)
        , size_(size)
        , start_(Clock::now())
    {}

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
