#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/linear_form.hpp"
#include "whir/canonical_config.hpp"
#include "whir/deterministic_rng.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/parameters.hpp"
#include "whir/protocols/whir_zk/whir_zk.hpp"
#include "whir/transcript/transcript.hpp"

#include <array>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

using F = ::whir::algebra::Goldilocks;

static std::ostream* out = &std::cout;
static std::ofstream out_file;

static void dump_bytes(const char* label, const std::vector<std::uint8_t>& data) {
    (*out) << "    " << label << ' ';
    auto flags = out->flags();
    auto fill = out->fill();
    for (auto b : data)
        (*out) << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(b);
    out->flags(flags);
    out->fill(fill);
    (*out) << '\n';
}

static void dump_field_vec(const char* label, const std::vector<F>& values) {
    (*out) << "    " << label;
    for (const auto& value : values)
        (*out) << ' ' << static_cast<unsigned long long>(value.as_canonical_u64());
    (*out) << '\n';
}

static void disable_whir_pow(::whir::protocols::whir::Config<::whir::algebra::Identity<F>>& config) {
    config.initial_sumcheck.round_pow.threshold_val = UINT64_MAX;
    config.initial_skip_pow.threshold_val = UINT64_MAX;
    for (auto& round : config.round_configs) {
        round.sumcheck.round_pow.threshold_val = UINT64_MAX;
        round.pow.threshold_val = UINT64_MAX;
    }
    config.final_sumcheck.round_pow.threshold_val = UINT64_MAX;
    config.final_pow.threshold_val = UINT64_MAX;
}

static void disable_zk_pow(::whir::protocols::whir_zk::ZkConfig<F>& config) {
    disable_whir_pow(config.blinded_commitment);
    disable_whir_pow(config.blinding_commitment);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        out_file.open(argv[1], std::ios::binary);
        if (!out_file) {
            std::cerr << "failed to open output file: " << argv[1] << '\n';
            return 2;
        }
        out = &out_file;
    }

    const std::size_t num_variables = 8;
    const std::size_t vector_size = std::size_t{1} << num_variables;
    const std::size_t num_polynomials = 1;

    ::whir::ProtocolParameters params;
    params.unique_decoding = false;
    params.security_level = 16;
    params.pow_bits = 0;
    params.initial_folding_factor = 2;
    params.folding_factor = 2;
    params.starting_log_inv_rate = 1;
    params.batch_size = 1;
    params.hash_id = ::whir::hash::ENGINE_ID_SHA2;

    ::whir::protocols::whir_zk::BlindingSizePolicy policy;
    policy.q_delta_1 = 4;
    policy.q_delta_2 = 4;
    policy.t1 = 4;
    policy.t2 = 4;
    policy.sumcheck_round_degree = 3;

    auto config = ::whir::protocols::whir_zk::ZkConfig<F>::from_params_with_policy(
        vector_size, params, num_polynomials, policy);
    disable_zk_pow(config);

    std::vector<F> poly(vector_size);
    for (std::size_t i = 0; i < vector_size; ++i)
        poly[i] = F::from_u64(static_cast<std::uint64_t>(i) * 17 + 3);
    std::vector<std::span<const F>> polys{std::span<const F>{poly}};

    std::vector<F> weight(vector_size, F::one());
    F evaluation = F::zero();
    for (const auto& value : poly) evaluation += value;
    std::vector<F> evaluations{evaluation};

    auto [canonical_config, ds] = ::whir::canonical_config::whir_zk_domain_separator(
        vector_size, num_polynomials, params, policy, "whir_zk_0");
    ::whir::transcript::Empty instance;
    auto prover_state = ::whir::transcript::ProverState::from_ds(ds, instance);

    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);
    ::whir::DeterministicRng rng(seed, "WHIR_ZK:mask");
    (*out) << "# SECTION whir_zk\n";
    dump_bytes("canonical_config", canonical_config);
    dump_bytes("ds_protocol_id", std::vector<std::uint8_t>{ds.protocol_id.begin(), ds.protocol_id.end()});
    dump_bytes("ds_session_id", std::vector<std::uint8_t>{ds.session_id.begin(), ds.session_id.end()});
    auto witness = config.commit(prover_state, polys, rng);
    dump_field_vec("input_vector0", poly);
    dump_field_vec("f_hat_vector0", witness.f_hat_vectors[0]);
    dump_field_vec("blinding_m_poly0", witness.blinding_polynomials[0].m_poly);
    dump_field_vec("blinding_vector0", witness.blinding_vectors[0]);

    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> prove_forms;
    prove_forms.push_back(std::make_unique<::whir::algebra::Covector<F>>(weight));

    auto _claim = config.prove(
        prover_state,
        std::span<const F>{poly},
        std::move(witness),
        std::move(prove_forms),
        evaluations,
        rng);

    auto proof = std::move(prover_state).proof();
    dump_bytes("proof_narg", proof.narg_string);
    dump_bytes("proof_hints", proof.hints);

    auto verifier_state = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    auto commitment = config.receive_commitments(verifier_state, num_polynomials);
    ::whir::algebra::Covector<F> verify_form(weight);
    std::vector<const ::whir::algebra::LinearForm<F>*> verify_forms{&verify_form};
    bool ok = config.verify(verifier_state, verify_forms, evaluations, commitment);
    (*out) << "    verify " << static_cast<int>(ok) << '\n';
    (*out) << "    check_eof " << static_cast<int>(verifier_state.check_eof()) << '\n';

    return ok ? 0 : 1;
}
