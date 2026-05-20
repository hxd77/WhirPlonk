#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"

#include "cuda/cuda_integration.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <span>
#include <vector>

using whir::algebra::Goldilocks;

static std::vector<Goldilocks> roots_for(std::size_t n) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    Goldilocks r = engine.root(n);
    std::vector<Goldilocks> roots;
    roots.reserve(n);
    Goldilocks acc = Goldilocks::one();
    for (std::size_t i = 0; i < n; ++i) {
        roots.push_back(acc);
        acc *= r;
    }
    return roots;
}

int main() {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    for (std::size_t n : {2ULL, 4ULL, 8ULL, 16ULL, 32ULL, 64ULL, 128ULL, 256ULL}) {
        std::vector<Goldilocks> cpu(n);
        for (std::size_t i = 0; i < n; ++i) {
            cpu[i] = Goldilocks::from_u64(0x123456789abcdef0ULL + i * 17);
        }
        std::vector<Goldilocks> gpu = cpu;
        auto roots = roots_for(n);
        auto& pool = whir::cuda::GpuPool::instance();
        pool.upload_roots(reinterpret_cast<const uint64_t*>(roots.data()), roots.size());

        engine.ntt_batch(std::span<Goldilocks>{cpu}, n);
        whir::cuda::gpu_ntt_batch(reinterpret_cast<uint64_t*>(gpu.data()),
                                  reinterpret_cast<const uint64_t*>(roots.data()),
                                  gpu.size(), n);

        std::size_t first_bad = n;
        for (std::size_t i = 0; i < n; ++i) {
            if (cpu[i] != gpu[i]) {
                first_bad = i;
                break;
            }
        }
        if (first_bad == n) {
            std::printf("n=%zu ok\n", n);
        } else {
            std::printf("n=%zu bad at %zu cpu=%llu gpu=%llu\n", n, first_bad,
                        static_cast<unsigned long long>(cpu[first_bad].as_canonical_u64()),
                        static_cast<unsigned long long>(gpu[first_bad].as_canonical_u64()));
        }
    }
}
