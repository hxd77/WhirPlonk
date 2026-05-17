#pragma once

// 对应 WHIR 中的 src/parameters.rs。
// ProtocolParameters: WHIR 协议的全局配置 struct。

#include "engines.hpp"

#include <cstddef>
#include <ostream>

namespace whir {

struct ProtocolParameters {
    bool unique_decoding = false;            //是否要求唯一解码 (vs 列表解码)
    std::size_t starting_log_inv_rate = 0;   //采样的对数逆码率
    std::size_t initial_folding_factor = 0;  //初始轮的折叠因子
    std::size_t folding_factor = 0;          //初始轮之后的折叠因子
    std::size_t security_level = 0;          //安全位数
    std::size_t pow_bits = 0;                //PoW 所需最大位数
    std::size_t batch_size = 0;              //批量提交的向量数
    EngineId hash_id = ENGINE_ID_NONE;       //哈希函数标识

    friend bool operator==(const ProtocolParameters&, const ProtocolParameters&) = default;

    //Rust Display: 两行格式化输出, 这里用 operator<< 等价。
    friend std::ostream& operator<<(std::ostream& os, const ProtocolParameters& p) {
        os << "Targeting " << p.security_level //安全位数
           << "-bits of security with " << p.pow_bits //PoW所需最大位数
           << "-bits of PoW using "
           << (p.unique_decoding ? "unique" : "list")
           << " decoding\n";
        os << "Starting rate: 2^-" << p.starting_log_inv_rate
           << ", initial_folding_factor: " << p.initial_folding_factor
           << ", folding_factor: " << p.folding_factor
           << "\n";
        return os;
    }
};

} // namespace whir
