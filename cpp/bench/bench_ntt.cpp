// ===========================================================================
// bench_ntt.cpp — NTT (数论变换) 性能基准测试
//
// 运行: ./bench_ntt [--batch N] [--runs N] [--warmups N] [--sizes S1 S2 ...]
//
// 测试 Goldilocks 域的 NTT 批量变换性能，输出 CSV 格式结果。
//
// 默认参数:
//   --batch 1        — 每次测试的批量大小
//   --runs 5         — 每个 size 的测试轮数
//   --warmups 1      — 预热轮数
//   --sizes 4096 16384 65536 262144 1048576  — 测试的 NTT 长度 (2^12 到 2^20)
//
// 输出格式 (CSV):
//   mode,cpu|cuda           — 编译模式
//   batch,N                 — 批量大小
//   runs,N                  — 测试轮数
//   warmups,N               — 预热轮数
//   n,total_elements,best_ms,avg_ms,checksum  — 每个 size 的结果
//
// 性能指标:
//   best_ms   — 最快一轮的耗时 (毫秒)
//   avg_ms    — 所有轮次的平均耗时 (毫秒)
//   checksum  — 输出数据的校验和 (用于验证正确性)
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <vector>

using whir::algebra::Goldilocks;

struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

static std::vector<Goldilocks> make_input(std::size_t n, std::size_t batch) {
    Lcg rng(0x4e54545f42454e43ULL ^ static_cast<uint64_t>(n) ^ (static_cast<uint64_t>(batch) << 32));
    std::vector<Goldilocks> values(n * batch);
    for (auto& v : values) v = Goldilocks::from_u64(rng.next());
    return values;
}

static uint64_t checksum(const std::vector<Goldilocks>& values) {
    uint64_t acc = 0x9e3779b97f4a7c15ULL;
    for (const auto& v : values) {
        uint64_t x = v.as_canonical_u64();
        acc ^= x + 0x9e3779b97f4a7c15ULL + (acc << 6) + (acc >> 2);
    }
    return acc;
}

static double run_once(std::vector<Goldilocks>& values, std::size_t n) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const auto t0 = std::chrono::steady_clock::now();
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
    const auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

int main(int argc, char** argv) {
    try {
    std::size_t batch = 1;
    int runs = 5;
    int warmups = 1;
    std::vector<std::size_t> sizes = {
        std::size_t{1} << 12,
        std::size_t{1} << 14,
        std::size_t{1} << 16,
        std::size_t{1} << 18,
        std::size_t{1} << 20
    };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--batch" && i + 1 < argc) batch = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
        else if (arg == "--runs" && i + 1 < argc) runs = std::atoi(argv[++i]);
        else if (arg == "--warmups" && i + 1 < argc) warmups = std::atoi(argv[++i]);
        else if (arg == "--sizes") {
            sizes.clear();
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                sizes.push_back(static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10)));
            }
        }
    }

    std::printf("mode,%s\n", 
#ifdef WHIR_CUDA
        "cuda"
#else
        "cpu"
#endif
    );
    std::printf("batch,%zu\n", batch);
    std::printf("runs,%d\n", runs);
    std::printf("warmups,%d\n", warmups);
    std::printf("n,total_elements,best_ms,avg_ms,checksum\n");

    for (std::size_t n : sizes) {
        for (int w = 0; w < warmups; ++w) {
            auto warm = make_input(n, batch);
            (void)run_once(warm, n);
        }

        double total_ms = 0.0;
        double best_ms = 1.0e300;
        uint64_t last_checksum = 0;
        for (int r = 0; r < runs; ++r) {
            auto values = make_input(n, batch);
            const double ms = run_once(values, n);
            total_ms += ms;
            best_ms = std::min(best_ms, ms);
            last_checksum = checksum(values);
        }

        std::printf("%zu,%zu,%.6f,%.6f,0x%016llx\n",
            n, n * batch, best_ms, total_ms / std::max(runs, 1),
            static_cast<unsigned long long>(last_checksum));
    }

    return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_ntt error: %s\n", e.what());
        return 2;
    }
}
