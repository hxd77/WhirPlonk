#include "whir/algebra/goldilocks.hpp"
#include "whir/deterministic_rng.hpp"

#include <array>
#include <cstdio>

//用固定seed初始化一个确定性随机数生成器DeterministcRng,然后依次输出随机字节、随机u64、随机Goldilocks域元素
using F = ::whir::algebra::Goldilocks;

//把一段字节数组打印成十六进制字符串
static void dump_hex(const char* label, const std::vector<std::uint8_t>& bytes) {
    std::printf("%s ", label);
    for (auto b : bytes) std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n");
}

//
int main() {
    //创建一个32字节的seed 00 01 02 03 04 ... 1f
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);

    ::whir::DeterministicRng rng(seed, "WHIR_ZK:mask");

    //# SECTION rng
    //domain WHIR_ZK:mask
    std::printf("# SECTION rng\n");
    std::printf("domain %s\n", rng.domain().c_str());
    dump_hex("bytes_0_64", rng.bytes(64)); //让随机数生成器生成64个字节,然后dump_hex把它们打印成十六进制
    //输出类似bytes_0_64 3a4f8c...

    //输出8个随机u64
    //输出类似u64 123456789 987654321 111111111 ...
    std::printf("u64");
    for (int i = 0; i < 8; ++i) std::printf(" %llu", static_cast<unsigned long long>(rng.u64()));
    std::printf("\n");

    //输出8个Goldilocks域元素
    //输出类似field64 12345 67890 99999 ...
    std::printf("field64");
    for (int i = 0; i < 8; ++i)
        std::printf(" %llu", static_cast<unsigned long long>(rng.goldilocks().as_canonical_u64()));
    std::printf("\n");

    return 0;
}
