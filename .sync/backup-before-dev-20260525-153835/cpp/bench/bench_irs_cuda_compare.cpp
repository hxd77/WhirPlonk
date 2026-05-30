#include "whir/algebra/embedding.hpp"
#include "whir/algebra/goldilocks.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/irs_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/transcript/transcript.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <span>
#include <string>
#include <vector>

using F = whir::algebra::Goldilocks;
using Emb = whir::algebra::Identity<F>;

struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

struct Case {
    std::size_t vector_size;
    std::size_t codeword_length;
    std::size_t interleaving_depth;
    std::size_t num_vectors;
    std::size_t in_domain_samples;
    std::size_t out_domain_samples;
};

struct Row {
    double commit_ms = 0.0;
    double open_ms = 0.0;
    double verify_ms = 0.0;
    double total_ms = 0.0;
    std::size_t proof_bytes = 0;
    std::size_t hint_bytes = 0;
    bool correct = false;
    bool gpu_available = false;
};

static whir::transcript::DomainSeparator make_ds() {
    whir::transcript::DomainSeparator ds;
    for (std::size_t i = 0; i < ds.protocol_id.size(); ++i) {
        ds.protocol_id[i] = static_cast<std::uint8_t>(0x31u + i * 7u);
    }
    for (std::size_t i = 0; i < ds.session_id.size(); ++i) {
        ds.session_id[i] = static_cast<std::uint8_t>(0xabu - i * 3u);
    }
    return ds;
}

static std::vector<std::vector<F>> make_vectors(const Case& c) {
    Lcg rng(0x49525342454e4348ULL ^ static_cast<uint64_t>(c.vector_size) ^
            (static_cast<uint64_t>(c.codeword_length) << 16) ^
            (static_cast<uint64_t>(c.num_vectors) << 32));
    std::vector<std::vector<F>> vectors(c.num_vectors);
    for (auto& vec : vectors) {
        vec.resize(c.vector_size);
        for (auto& v : vec) v = F::from_u64(rng.next());
    }
    return vectors;
}

static std::vector<std::span<const F>> make_spans(const std::vector<std::vector<F>>& vectors) {
    std::vector<std::span<const F>> spans;
    spans.reserve(vectors.size());
    for (const auto& v : vectors) spans.emplace_back(v);
    return spans;
}

static whir::protocols::irs_commit::Config<Emb> make_config(const Case& c) {
    whir::protocols::irs_commit::Config<Emb> config;
    config.num_vectors = c.num_vectors;
    config.vector_size = c.vector_size;
    config.codeword_length = c.codeword_length;
    config.interleaving_depth = c.interleaving_depth;
    config.matrix_commit_num_cols = c.num_vectors * c.interleaving_depth;
    config.in_domain_samples = c.in_domain_samples;
    config.out_domain_samples = c.out_domain_samples;
    config.deduplicate_in_domain = true;
    config.matrix_commit_mt = whir::protocols::merkle_tree::make_config(
        whir::hash::ENGINE_ID_SHA2, c.codeword_length);
    return config;
}

static Row run_protocol(const Case& c, bool use_cuda) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(use_cuda);
    whir::cuda::set_gpu_ntt_threshold(use_cuda ? 0 : old_threshold);
#else
    (void)use_cuda;
#endif

    const auto vectors = make_vectors(c);
    const auto spans = make_spans(vectors);
    const auto config = make_config(c);
    const auto ds = make_ds();
    whir::transcript::Empty instance;

    auto ps = whir::transcript::ProverState::from_ds(ds, instance);
    const auto commit_t0 = std::chrono::steady_clock::now();
    auto witness = config.commit(ps, std::span<const std::span<const F>>{spans});
    const auto commit_t1 = std::chrono::steady_clock::now();

    std::vector<const whir::protocols::irs_commit::Witness<F, F>*> wlist{&witness};
    const auto open_t0 = std::chrono::steady_clock::now();
    auto opened = config.open(ps, std::span<const whir::protocols::irs_commit::Witness<F, F>*>{wlist});
    const auto open_t1 = std::chrono::steady_clock::now();

    auto proof = std::move(ps).proof();

    auto vs = whir::transcript::VerifierState::from_ds(ds, instance, proof);
    const auto verify_t0 = std::chrono::steady_clock::now();
    auto commitment = config.receive_commitment(vs);
    std::vector<const whir::protocols::irs_commit::Commitment<F>*> clist{&commitment};
    auto verified = config.verify(vs, std::span<const whir::protocols::irs_commit::Commitment<F>*>{clist});
    const auto verify_t1 = std::chrono::steady_clock::now();

    Row row;
    row.commit_ms = std::chrono::duration<double, std::milli>(commit_t1 - commit_t0).count();
    row.open_ms = std::chrono::duration<double, std::milli>(open_t1 - open_t0).count();
    row.verify_ms = std::chrono::duration<double, std::milli>(verify_t1 - verify_t0).count();
    row.total_ms = row.commit_ms + row.open_ms + row.verify_ms;
    row.proof_bytes = proof.narg_string.size();
    row.hint_bytes = proof.hints.size();
    row.correct = (opened.points == verified.points) && (opened.matrix == verified.matrix) &&
                  vs.check_eof();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    row.gpu_available = use_cuda && whir::cuda::last_ntt_timing().used_gpu;
    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
    return row;
}

int main(int argc, char** argv) {
    try {
        int runs = 3;
        int warmups = 1;
        std::vector<Case> cases = {
            {std::size_t{1} << 8,  std::size_t{1} << 10, 4, 4, 8, 1},
            {std::size_t{1} << 10, std::size_t{1} << 12, 4, 4, 8, 1},
            {std::size_t{1} << 12, std::size_t{1} << 14, 4, 4, 8, 1},
            {std::size_t{1} << 14, std::size_t{1} << 16, 4, 4, 8, 1},
            {std::size_t{1} << 16, std::size_t{1} << 18, 4, 4, 8, 1},
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--runs" && i + 1 < argc) runs = std::atoi(argv[++i]);
            else if (arg == "--warmups" && i + 1 < argc) warmups = std::atoi(argv[++i]);
        }

        std::printf("vector_size,codeword_length,depth,num_vectors,cpu_commit_ms,cpu_open_ms,"
                    "cpu_verify_ms,cpu_total_ms,gpu_commit_ms,gpu_open_ms,gpu_verify_ms,"
                    "gpu_total_ms,total_speedup,proof_bytes,hint_bytes,correctness\n");

        for (const auto& c : cases) {
            for (int w = 0; w < std::max(warmups, 0); ++w) {
                (void)run_protocol(c, true);
            }

            Row best_cpu;
            best_cpu.total_ms = 1.0e300;
            Row best_gpu;
            best_gpu.total_ms = 1.0e300;
            bool correct = true;
            for (int r = 0; r < std::max(runs, 1); ++r) {
                const auto cpu = run_protocol(c, false);
                if (cpu.total_ms < best_cpu.total_ms) best_cpu = cpu;
                const auto gpu = run_protocol(c, true);
                if (gpu.total_ms < best_gpu.total_ms) best_gpu = gpu;
                correct = correct && cpu.correct && gpu.correct;
            }

            const double speedup =
                best_gpu.total_ms > 0.0 && best_gpu.gpu_available ? best_cpu.total_ms / best_gpu.total_ms : 0.0;
            std::printf("%zu,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%zu,%zu,%s\n",
                        c.vector_size, c.codeword_length, c.interleaving_depth, c.num_vectors,
                        best_cpu.commit_ms, best_cpu.open_ms, best_cpu.verify_ms, best_cpu.total_ms,
                        best_gpu.commit_ms, best_gpu.open_ms, best_gpu.verify_ms, best_gpu.total_ms,
                        speedup, best_gpu.proof_bytes, best_gpu.hint_bytes,
                        best_gpu.gpu_available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_irs_cuda_compare error: %s\n", e.what());
        return 2;
    }
}
