#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"

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

struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

struct Case {
    std::size_t poly_size;
    std::size_t codeword_length;
    std::size_t interleaving_depth;
    std::size_t num_polys;
};

static std::vector<std::vector<Goldilocks>> make_coeffs(const Case& c) {
    Lcg rng(0x52535f454e434f44ULL ^ static_cast<uint64_t>(c.poly_size) ^
            (static_cast<uint64_t>(c.codeword_length) << 16) ^
            (static_cast<uint64_t>(c.interleaving_depth) << 32) ^
            (static_cast<uint64_t>(c.num_polys) << 48));
    std::vector<std::vector<Goldilocks>> coeffs(c.num_polys);
    for (auto& poly : coeffs) {
        poly.resize(c.poly_size);
        for (auto& v : poly) v = Goldilocks::from_u64(rng.next());
    }
    return coeffs;
}

static std::vector<std::span<const Goldilocks>> make_spans(
    const std::vector<std::vector<Goldilocks>>& coeffs) {
    std::vector<std::span<const Goldilocks>> spans;
    spans.reserve(coeffs.size());
    for (const auto& poly : coeffs) spans.emplace_back(poly);
    return spans;
}

static uint64_t checksum(const std::vector<Goldilocks>& values) {
    uint64_t acc = 0x9e3779b97f4a7c15ULL;
    for (const auto& v : values) {
        uint64_t x = v.as_canonical_u64();
        acc ^= x + 0x9e3779b97f4a7c15ULL + (acc << 6) + (acc >> 2);
    }
    return acc;
}

static double run_once(const Case& c, uint64_t& out_checksum) {
    auto coeffs = make_coeffs(c);
    auto spans = make_spans(coeffs);
    auto& engine = whir::algebra::ntt::goldilocks_engine();

    const auto t0 = std::chrono::steady_clock::now();
    auto encoded = whir::algebra::ntt::interleaved_rs_encode<Goldilocks>(
        engine, std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth);
    const auto t1 = std::chrono::steady_clock::now();

    out_checksum = checksum(encoded);
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

int main(int argc, char** argv) {
    try {
        int runs = 5;
        int warmups = 1;
        std::vector<Case> cases = {
            {std::size_t{1} << 12, std::size_t{1} << 14, 4, 4},
            {std::size_t{1} << 14, std::size_t{1} << 16, 4, 4},
            {std::size_t{1} << 16, std::size_t{1} << 18, 4, 4},
            {std::size_t{1} << 18, std::size_t{1} << 20, 4, 4},
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--runs" && i + 1 < argc) runs = std::atoi(argv[++i]);
            else if (arg == "--warmups" && i + 1 < argc) warmups = std::atoi(argv[++i]);
            else if (arg == "--case" && i + 4 < argc) {
                cases.clear();
                Case c{};
                c.poly_size = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                c.codeword_length = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                c.interleaving_depth = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                c.num_polys = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                cases.push_back(c);
            }
        }

        std::printf("mode,%s\n",
#ifdef WHIR_CUDA
            "cuda"
#else
            "cpu"
#endif
        );
        std::printf("runs,%d\n", runs);
        std::printf("warmups,%d\n", warmups);
        std::printf("poly_size,codeword_length,interleaving_depth,num_polys,total_elements,best_ms,avg_ms,checksum\n");

        for (const auto& c : cases) {
            for (int w = 0; w < warmups; ++w) {
                uint64_t ignored = 0;
                (void)run_once(c, ignored);
            }

            double total_ms = 0.0;
            double best_ms = 1.0e300;
            uint64_t last_checksum = 0;
            for (int r = 0; r < runs; ++r) {
                uint64_t out = 0;
                const double ms = run_once(c, out);
                total_ms += ms;
                best_ms = std::min(best_ms, ms);
                last_checksum = out;
            }

            const std::size_t total_elements = c.codeword_length * c.interleaving_depth * c.num_polys;
            std::printf("%zu,%zu,%zu,%zu,%zu,%.6f,%.6f,0x%016llx\n",
                c.poly_size, c.codeword_length, c.interleaving_depth, c.num_polys,
                total_elements, best_ms, total_ms / std::max(runs, 1),
                static_cast<unsigned long long>(last_checksum));
        }

        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_rs_encode error: %s\n", e.what());
        return 2;
    }
}
