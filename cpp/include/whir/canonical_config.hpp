#pragma once

#include "whir/parameters.hpp"
#include "whir/protocols/whir_zk/whir_zk.hpp"
#include "whir/transcript/transcript.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace whir::canonical_config {

inline void push_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

inline void push_cbor_text(std::vector<std::uint8_t>& out, std::string_view text) {
    if (text.size() <= 23) {
        out.push_back(static_cast<std::uint8_t>(0x60 + text.size()));
    } else if (text.size() <= 0xff) {
        out.push_back(0x78);
        out.push_back(static_cast<std::uint8_t>(text.size()));
    } else {
        out.push_back(0x79);
        out.push_back(static_cast<std::uint8_t>((text.size() >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(text.size() & 0xff));
    }
    out.insert(out.end(), text.begin(), text.end());
}

inline std::vector<std::uint8_t> whir_zk_config_bytes(
    std::size_t vector_size,
    std::size_t num_polynomials,
    const ::whir::ProtocolParameters& params,
    const ::whir::protocols::whir_zk::BlindingSizePolicy& policy)
{
    std::vector<std::uint8_t> out;
    constexpr std::string_view magic = "WHIR_ZK_CONFIG_V1";
    out.insert(out.end(), magic.begin(), magic.end());
    push_u64(out, vector_size);
    push_u64(out, num_polynomials);
    out.push_back(params.unique_decoding ? 1 : 0);
    push_u64(out, params.starting_log_inv_rate);
    push_u64(out, params.initial_folding_factor);
    push_u64(out, params.folding_factor);
    push_u64(out, params.security_level);
    push_u64(out, params.pow_bits);
    push_u64(out, params.batch_size);
    const auto& hash_id = params.hash_id.bytes();
    out.insert(out.end(), hash_id.begin(), hash_id.end());
    push_u64(out, policy.q_delta_1);
    push_u64(out, policy.q_delta_2);
    push_u64(out, policy.t1);
    push_u64(out, policy.t2);
    push_u64(out, policy.sumcheck_round_degree);
    return out;
}

inline ::whir::transcript::DomainSeparator domain_separator_from_config_bytes(
    std::span<const std::uint8_t> config_bytes,
    std::string_view session)
{
    ::whir::transcript::DomainSeparator ds;
    sha3_512_hash(config_bytes.data(), config_bytes.size(), ds.protocol_id.data());

    std::vector<std::uint8_t> session_cbor;
    push_cbor_text(session_cbor, session);
    sha3_256_hash(session_cbor.data(), session_cbor.size(), ds.session_id.data());
    return ds;
}

inline std::pair<std::vector<std::uint8_t>, ::whir::transcript::DomainSeparator>
whir_zk_domain_separator(
    std::size_t vector_size,
    std::size_t num_polynomials,
    const ::whir::ProtocolParameters& params,
    const ::whir::protocols::whir_zk::BlindingSizePolicy& policy,
    std::string_view session)
{
    auto config_bytes = whir_zk_config_bytes(vector_size, num_polynomials, params, policy);
    auto ds = domain_separator_from_config_bytes(config_bytes, session);
    return {std::move(config_bytes), ds};
}

} // namespace whir::canonical_config
