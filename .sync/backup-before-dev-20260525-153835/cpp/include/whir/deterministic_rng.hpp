#pragma once

#include "whir/algebra/goldilocks.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

extern "C" {
#include "blake3.h"
}

namespace whir {

class DeterministicRng {
public:
    static constexpr std::string_view kPersonalization = "WHIR_DETERMINISTIC_RNG_V1";

    DeterministicRng(std::array<std::uint8_t, 32> seed, std::string domain)
        : seed_(seed), domain_(std::move(domain)) {}

    std::vector<std::uint8_t> bytes(std::size_t n) {
        std::vector<std::uint8_t> out(n);
        fill(out);
        return out;
    }

    void fill(std::span<std::uint8_t> out) {
        std::size_t written = 0;
        while (written < out.size()) {
            if (buffer_pos_ == buffer_.size()) refill();
            const std::size_t take = std::min(out.size() - written, buffer_.size() - buffer_pos_);
            std::memcpy(out.data() + written, buffer_.data() + buffer_pos_, take);
            buffer_pos_ += take;
            written += take;
        }
    }

    std::uint64_t u64() {
        std::array<std::uint8_t, 8> buf{};
        fill(buf);
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) value |= std::uint64_t{buf[i]} << (8 * i);
        return value;
    }

    // Compatibility with existing C++ field samplers such as Goldilocks::random(rng).
    std::uint64_t next() { return u64(); }

    ::whir::algebra::Goldilocks goldilocks() {
        return ::whir::algebra::Goldilocks::from_u64(u64());
    }

    std::vector<::whir::algebra::Goldilocks> goldilocks_vec(std::size_t n) {
        std::vector<::whir::algebra::Goldilocks> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) out.push_back(goldilocks());
        return out;
    }

    std::uint64_t counter() const { return counter_; }
    const std::string& domain() const { return domain_; }

private:
    static void push_u32_le(std::vector<std::uint8_t>& out, std::uint32_t value) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }

    static void push_u64_le(std::vector<std::uint8_t>& out, std::uint64_t value) {
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }

    void refill() {
        std::vector<std::uint8_t> input;
        input.reserve(kPersonalization.size() + 4 + domain_.size() + seed_.size() + 8);
        input.insert(input.end(), kPersonalization.begin(), kPersonalization.end());
        push_u32_le(input, static_cast<std::uint32_t>(domain_.size()));
        input.insert(input.end(), domain_.begin(), domain_.end());
        input.insert(input.end(), seed_.begin(), seed_.end());
        push_u64_le(input, counter_++);

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, input.data(), input.size());
        blake3_hasher_finalize(&hasher, buffer_.data(), buffer_.size());
        buffer_pos_ = 0;
    }

    std::array<std::uint8_t, 32> seed_{};
    std::string domain_;
    std::uint64_t counter_ = 0;
    std::array<std::uint8_t, 32> buffer_{};
    std::size_t buffer_pos_ = 32;
};

} // namespace whir
