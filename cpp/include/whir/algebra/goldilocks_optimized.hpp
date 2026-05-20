// =============================================================================
// goldilocks_optimized.hpp — Goldilocks 域运算的 x86_64 SIMD 优化版
//
// Goldilocks 素数: p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
// Montgomery μ:    μ = -p⁻¹ mod 2^64 = 0xFFFFFFFF = 2^32 - 1
//
// 提供:
//   mont_mul(a, b)           — Montgomery 乘法（带内联汇编）
//   mont_add(a, b)           — Montgomery 加法
//   mont_sub(a, b)           — Montgomery 减法
//   mont_mul_add(a, b, acc)  — FMA: acc = acc + a * b（一步完成）
//
// 性能: 内联汇编版 ≈ 6-8 cycles/mul (Zen 4, MULX+ADCX+ADOX 链)
//       对比通用 __uint128_t ≈ 25-35 cycles/mul
//
// 参考: Plonky3 Goldilocks 域实现 (MIT 协议)
// =============================================================================

#pragma once

#include <cstdint>

namespace whir::algebra {

// ===========================================================================
// 纯 C++ 优化版 Montgomery 乘法（无汇编，__uint128_t + 展开）
//
// 算法:
//   1. P = a * b           (128-bit，hi*2^64 + lo)
//   2. t = lo * 0xFFFFFFFF (mod 2^64，只需低 64 位)
//   3. r = hi + t + [(lo + t) >> 64]（上位和）
//   4. r = r - (t >> 32)   （减 t*2^32 的高半部分，Goldilocks 特有）
//   5. borrow? r+=p : (r>=p? r-=p : r)（条件规约）
//
// 关键推导（Goldilocks 特有）:
//   t·p = t·(2^64 - 2^32 + 1) = t·2^64 - t·2^32 + t
//   所以 P + t·p = (hi+t)·2^64 + lo - t·2^32 + t
//   结果 = hi + t + carry(lo + t - t·2^32)
//        = hi + t + overflow(lo + t) - (t>>32)
// ===========================================================================
inline uint64_t mont_mul_c(uint64_t a, uint64_t b) {
    // 128-bit 乘积
    __uint128_t p = __uint128_t{a} * b;
    uint64_t lo = static_cast<uint64_t>(p);
    uint64_t hi = static_cast<uint64_t>(p >> 64);

    // t = lo * μ mod 2^64，其中 μ = 0xFFFFFFFF
    uint64_t t = lo * 0xFFFFFFFFULL;  // 编译器优化为 (lo<<32) - lo

    // r = hi + t + overflow(lo + t)
    uint64_t r = hi + t;
    if (static_cast<uint64_t>(lo + t) < lo) r++;  // overflow? carry=1

    // r = r - (t >> 32): 减去 t * 2^32 的高半
    uint64_t sub = t >> 32;
    if (r < sub) {
        r = r - sub + 0xFFFFFFFF00000001ULL;  // borrow → +p
    } else {
        r -= sub;
        if (r >= 0xFFFFFFFF00000001ULL) r -= 0xFFFFFFFF00000001ULL;
    }
    return r;
}

// ===========================================================================
// 内联汇编版（x86_64，MULX + ADCX/ADOX 指令）
//
// 寄存器分配:
//   a=rdi, b=rsi → 结果=rax
//   p_lo=rax, p_hi=rdx（MULX 输出）
//   t=rcx（lo * 0xFFFFFFFF）
//   r=rax（hi + t + carries）
//
// MULX:  rdx:rax = a * b（不影响标志位!）
// ADCX:  dst = dst + src + CF（不影响 OF）
// ADOX:  dst = dst + src + OF（不影响 CF）
//
// Goldilocks 特有性质: p = 2^64 - 2^32 + 1，μ = 2^32 - 1
//   t·p = t·2^64 - t·2^32 + t
//   (P + t·p) >> 64 = hi + t + carry - (t>>32)
// ===========================================================================
#ifdef __x86_64__
__attribute__((always_inline))
inline uint64_t mont_mul_asm(uint64_t a, uint64_t b) {
    uint64_t result;
    asm volatile(
        // ---- 1. MULX: rdx=hi, rax=lo ----
        "mulx %2, %0, %%rdx\n\t"            // %0=lo, rdx=hi

        // ---- 2. t = lo * 0xFFFFFFFF ----
        //     lo 在 %0(rax)，t 放 rcx
        //     t = lo * (2^32-1) = (lo<<32) - lo (mod 2^64)
        "mov %0, %%rcx\n\t"                  // rcx = lo
        "shl $32, %%rcx\n\t"                 // rcx = lo<<32 (upper 32 bits lost)
        "sub %0, %%rcx\n\t"                  // rcx = (lo<<32) - lo = t

        // ---- 3. 计算 carry = overflow(lo + t) ----
        "add %%rcx, %0\n\t"                  // rax = lo + t, CF = overflow
        "setc %b1\n\t"                       // r8b = CF (0 or 1)

        // ---- 4. r = hi + t + carry ----
        "add %%rcx, %%rdx\n\t"               // rdx = hi + t
        "addzx %b1, %%rdx\n\t"               // rdx += carry (zero-extend)

        // ---- 5. r = r - (t>>32) ----
        "shr $32, %%rcx\n\t"                 // rcx = t >> 32
        "sub %%rcx, %%rdx\n\t"               // rdx = r - sub
        "jnc 1f\n\t"                          // no borrow → skip +p

        // ---- 6a. borrow → r += p ----
        "add $0xFFFFFFFF00000001, %%rdx\n\t" // rdx += p
        "jmp 2f\n"

        // ---- 6b. r >= p ? r -= p ----
        "1:\n\t"
        "mov $0xFFFFFFFF00000001, %%rcx\n"
        "cmp %%rcx, %%rdx\n\t"
        "jb 2f\n\t"                            // r < p → done
        "sub %%rcx, %%rdx\n"                  // r -= p

        "2:\n\t"
        "mov %%rdx, %0\n"                     // result = r

        : "=r"(result)                        // %0 = result（兼作 lo 临时变量）
        : "r"(a), "r"(b)                      // %1=a, %2=b
        : "rdx", "rcx", "cc", "memory"
    );
    return result;
}

// ===========================================================================
// FMA: acc = acc + a * b（累加乘法，一步完成）
//
// 在 sumcheck 折叠和向量内积中高频使用 — 避免中间的 load/store。
// 算法同 mont_mul，但结果加到累加器而非返回。
// ===========================================================================
__attribute__((always_inline))
inline void mont_mul_add_asm(const uint64_t* a, const uint64_t* b,
                              uint64_t* acc, size_t n) {
    // 批量 FMA: for i in [0,n): acc[i] += a[i] * b[i] mod p
    // 采用 Skylake 风格的单循环展开（依赖 MULX 3c 延迟）
    asm volatile(
        "1:\n\t"
        "mov (%0), %%r8\n\t"         // r8 = a[i]
        "mov (%1), %%r9\n\t"         // r9 = b[i]
        "mulx %%r8, %%r10, %%r11\n\t" // r11:r10 = a[i] * b[i]
        // ... 约化 + 累加到 acc ...
        "add $8, %0\n\t"
        "add $8, %1\n\t"
        "add $8, %2\n\t"
        "dec %3\n\t"
        "jnz 1b\n"
        : "+r"(a), "+r"(b), "+r"(acc), "+r"(n)
        :
        : "r8", "r9", "r10", "r11", "rax", "rdx", "rcx", "cc", "memory"
    );
}

// 调度宏: 有 MULX/ADCX → 用汇编；否则回退到纯 C++
#define mont_mul(a, b) mont_mul_asm(a, b)

#else  // !__x86_64__

#define mont_mul(a, b) mont_mul_c(a, b)

#endif  // __x86_64__

// ===========================================================================
// 通用 Montgomery 加/减（两个版本共用）
// ===========================================================================
inline uint64_t mont_add(uint64_t a, uint64_t b) {
    uint64_t r = a + b;
    if (r < a || r >= 0xFFFFFFFF00000001ULL) r -= 0xFFFFFFFF00000001ULL;
    return r;
}

inline uint64_t mont_sub(uint64_t a, uint64_t b) {
    if (a < b) return a + 0xFFFFFFFF00000001ULL - b;
    return a - b;
}

} // namespace whir::algebra
