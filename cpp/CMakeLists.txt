# ============================================================================
# CMakeLists.txt — WHIR C++ 项目的顶层构建脚本
# ============================================================================
#
# 这个文件是整个 C++ 版本 WHIR 项目的“构建入口”。
# CMake 会从这里开始读取规则，然后决定：
#   1. 使用哪些编译器语言：C / C++ / CUDA
#   2. 生成哪些库：第三方哈希库、header-only algebra 库、CUDA 静态库
#   3. 生成哪些可执行程序：CLI、benchmark、测试程序
#   4. 是否启用 OpenMP、CUDA、BLAKE3 SIMD 等性能优化选项
#
# 项目中的核心目标：
#
#   whir_thirdparty (STATIC)
#       静态库，包含 vendored 的 C 语言依赖：
#       - BLAKE3
#       - SHA-256
#       - Keccak
#
#   whir_algebra (INTERFACE)
#       header-only 目标，本身不编译源码。
#       作用是向依赖它的目标暴露 include 路径、编译宏和链接依赖。
#
#   whir_cuda (STATIC，可选)
#       CUDA 静态库，只有 WHIR_CUDA=ON 时才会生成。
#       主要用于 GPU NTT / RS encoding 加速。
#
#   whir_cli
#       主命令行工具，入口文件是 main.cpp。
#
#   bench_*
#       多个性能测试程序，用于比较 CPU / GPU、哈希、Merkle、RS encode 等模块。
#
#   tests/
#       测试与 dumper 子目录，通过 add_subdirectory(tests) 加入。
#
# 常见构建示例：
#
#   CPU-only:
#       cmake -S . -B build -DWHIR_CUDA=OFF
#       cmake --build build --config Release
#
#   启用 CUDA:
#       cmake -S . -B build_cuda -DWHIR_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=75
#       cmake --build build_cuda --config Release
#
#   指定 RTX 4090 架构 sm_89:
#       cmake -S . -B build_cuda -DWHIR_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=89
#
# ============================================================================


# 要求 CMake 最低版本为 3.16。
# 如果用户机器上的 CMake 版本低于这个值，CMake 会直接报错。
cmake_minimum_required(VERSION 3.16)

# 声明项目名称为 whir_cpp。
# LANGUAGES C CXX 表示该项目默认启用 C 和 C++。
# 注意：这里没有默认启用 CUDA，因为 CUDA 是可选功能；
# 只有 WHIR_CUDA=ON 时，后面才会通过 enable_language(CUDA) 启用 CUDA。
project(whir_cpp LANGUAGES C CXX)


# ----------------------------------------------------------------------------
# 默认构建类型
# ----------------------------------------------------------------------------
#
# CMAKE_BUILD_TYPE 用于单配置生成器，例如 Makefile、Ninja。
# CMAKE_CONFIGURATION_TYPES 用于多配置生成器，例如 Visual Studio、Xcode。
#
# 这里的意思是：
#   如果当前不是多配置生成器，并且用户没有手动指定 CMAKE_BUILD_TYPE，
#   那么默认使用 Release。
#
# 这样可以避免用户直接 cmake -S . -B build 时生成 Debug 版本，
# 因为 Debug 版本通常没有优化，benchmark 数据会很差。
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Generator: ${CMAKE_GENERATOR}")
if(CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Multi-config build types: ${CMAKE_CONFIGURATION_TYPES}")
else()
    message(STATUS "Single-config build type: ${CMAKE_BUILD_TYPE}")
endif()


# ----------------------------------------------------------------------------
# C / C++ 标准设置
# ----------------------------------------------------------------------------
#
# C 标准设置为 C11。
# CXX 标准设置为 C++20。
#
# CMAKE_CXX_EXTENSIONS OFF 表示禁用编译器私有扩展，
# 尽量使用标准 C++20，而不是 GNU++20 这类扩展模式。
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WHIR_NATIVE_CPU "Enable native CPU instruction selection for local benchmarks" ON)
option(WHIR_ENABLE_O3 "Prefer aggressive optimization flags for release builds" ON)
option(WHIR_ENABLE_LTO "Enable C/C++ link-time optimization when supported" ON)
option(WHIR_CUDA_PTXAS_INFO "Print CUDA register/spill usage from ptxas" OFF)

if(WHIR_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT WHIR_IPO_SUPPORTED LANGUAGES C CXX)
    if(WHIR_IPO_SUPPORTED)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            find_program(WHIR_GCC_AR NAMES gcc-ar)
            find_program(WHIR_GCC_RANLIB NAMES gcc-ranlib)
            if(WHIR_GCC_AR AND WHIR_GCC_RANLIB)
                set(CMAKE_AR "${WHIR_GCC_AR}" CACHE FILEPATH "Archiver for GCC LTO objects" FORCE)
                set(CMAKE_RANLIB "${WHIR_GCC_RANLIB}" CACHE FILEPATH "Ranlib for GCC LTO objects" FORCE)
            endif()
        endif()
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
        message(STATUS "C/C++ LTO enabled for Release builds")
    else()
        message(STATUS "C/C++ LTO requested but not supported by this toolchain")
    endif()
endif()


# ----------------------------------------------------------------------------
# 本地 CPU 指令集优化
# ----------------------------------------------------------------------------
#
# 对 GCC / Clang：
#   -march=native 会让编译器根据当前机器 CPU 自动启用可用指令集，
#   例如 AVX2、AVX512、BMI、ADX 等。
#
# 优点：
#   本机性能更好。
#
# 缺点：
#   编译出来的二进制可能不能在较老 CPU 上运行。
#
# 注意：
#   MSVC 不支持 -march=native，所以这里只对 GNU / Clang 启用。
if(WHIR_NATIVE_CPU AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-march=native)
endif()

if(WHIR_ENABLE_O3 AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options($<$<CONFIG:Release>:-O3>)
endif()


# ----------------------------------------------------------------------------
# OpenMP：CPU 多线程加速
# ----------------------------------------------------------------------------
#
# WHIR_OPENMP 是一个 CMake 选项：
#   ON  表示启用 OpenMP
#   OFF 表示禁用 OpenMP
#
# 默认值是 ON。
#
# find_package(OpenMP REQUIRED) 会查找当前编译环境是否支持 OpenMP。
# 如果找不到 OpenMP，因为 REQUIRED，CMake 会直接报错。
#
# CMAKE_CXX_FLAGS 追加 OpenMP_CXX_FLAGS 后，C++ 编译命令会带上 OpenMP 参数，
# 例如 GCC/Clang 常见是 -fopenmp。
option(WHIR_OPENMP "Enable OpenMP multi-threading" ON)

if(WHIR_OPENMP)
    find_package(OpenMP REQUIRED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    message(STATUS "OpenMP enabled")
else()
    message(STATUS "OpenMP disabled — single-threaded build")
endif()


# ----------------------------------------------------------------------------
# CUDA：GPU 加速 NTT / RS Encoding
# ----------------------------------------------------------------------------
#
# WHIR_CUDA:
#   控制是否启用 CUDA 的选项。
#
# WHIR_CUDA_EXPERIMENTAL_NTT:
#   是否启用实验性的 CUDA NTT / RS encoding dispatch 路径。
#
# 启用 CUDA 需要：
#   1. 安装 NVIDIA Driver
#   2. 安装 CUDA Toolkit
#   3. CMake 能找到 nvcc
#   4. 设置合适的 CMAKE_CUDA_ARCHITECTURES
#
# 常见 GPU 架构：
#   T400 / Turing:    75
#   RTX 30 系 / Ampere: 86
#   RTX 4090 / Ada:   89
option(WHIR_CUDA "Enable CUDA GPU acceleration" OFF)
option(WHIR_CUDA_EXPERIMENTAL_NTT "Enable CUDA dispatch for Goldilocks NTT/RS encoding" ON)

if(WHIR_CUDA)
    # 当 WHIR_CUDA=ON 时，才启用 CUDA 语言。
    # 如果 nvcc 或 CUDA Toolkit 配置有问题，通常会在这里报错。
    enable_language(CUDA)

    # CUDA 源文件使用 C++17 标准。
    # 这里没有使用 C++20，是因为 nvcc 对新标准支持可能受版本影响。
    set(CMAKE_CUDA_STANDARD 17)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)

    # 如果用户没有指定 CMAKE_CUDA_ARCHITECTURES，
    # 默认编译 sm_75，即 Turing 及以上较常见的最低目标。
    #
    # 如果你用 RTX 4090，建议命令行传：
    #   -DCMAKE_CUDA_ARCHITECTURES=89
    #
    # 如果你用 NVIDIA T400，sm_75 是合适的。
    if(NOT CMAKE_CUDA_ARCHITECTURES)
        set(CMAKE_CUDA_ARCHITECTURES 75)
    endif()

    # 构建 CUDA 静态库 whir_cuda。
    # 目前只编译 cuda/cuda_ntt.cu。
    # 后续如果有更多 .cu 文件，可以继续追加到这里。
    add_library(whir_cuda STATIC cuda/cuda_ntt.cu)

    # 给 whir_cuda 暴露项目根目录作为 include 路径。
    # PUBLIC 表示：
    #   whir_cuda 自己能用；
    #   链接 whir_cuda 的其他目标也能继承这个 include 路径。
    target_include_directories(whir_cuda PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

    # 给编译 whir_cuda 和依赖它的目标定义 WHIR_CUDA 宏。
    # C++ 代码中可以通过 #ifdef WHIR_CUDA 判断是否启用了 CUDA。
    target_compile_definitions(whir_cuda PUBLIC WHIR_CUDA)

    # Windows + MSVC 下，给 CUDA 编译器转发 /utf-8，
    # 避免中文注释或字符串在 MSVC 下出现编码问题。
    if(MSVC)
        target_compile_options(whir_cuda PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/utf-8>)
    endif()

    target_compile_options(whir_cuda PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:-O3>
        $<$<AND:$<COMPILE_LANGUAGE:CUDA>,$<BOOL:${WHIR_CUDA_PTXAS_INFO}>>:-Xptxas=-v>
    )

    # 如果启用了实验性 CUDA NTT，
    # 则定义 WHIR_CUDA_EXPERIMENTAL_NTT 宏。
    # 代码里可以用这个宏控制是否走 GPU NTT dispatch。
    if(WHIR_CUDA_EXPERIMENTAL_NTT)
        target_compile_definitions(whir_cuda PUBLIC WHIR_CUDA_EXPERIMENTAL_NTT)
    endif()

    message(STATUS "CUDA enabled (GPU NTT + encoding, arch=sm_${CMAKE_CUDA_ARCHITECTURES})")
    message(STATUS "CUDA experimental NTT dispatch: ${WHIR_CUDA_EXPERIMENTAL_NTT}")
else()
    message(STATUS "CUDA disabled — CPU-only build")
endif()


# ----------------------------------------------------------------------------
# MSVC 编码设置
# ----------------------------------------------------------------------------
#
# /utf-8 用于告诉 MSVC：
#   源文件按 UTF-8 编码读取；
#   执行字符集也尽量按 UTF-8 处理。
#
# 这样可以减少 Windows 下中文注释、中文字符串导致的乱码或编译警告。
if(MSVC)
    add_compile_options(/utf-8)
endif()


# ============================================================================
# whir_thirdparty：第三方 C 依赖静态库
# ============================================================================
#
# 这个库把项目 vendored 进来的 C 语言依赖统一编译成一个静态库。
#
# STATIC 表示生成静态库：
#   Linux 通常是 libwhir_thirdparty.a
#   Windows 通常是 whir_thirdparty.lib
#
# 包含的源文件：
#   BLAKE3:
#       blake3.c
#       blake3_dispatch.c
#       blake3_portable.c
#
#   SHA-256:
#       sha256.c
#
#   Keccak:
#       keccak.c
#
# 这些哈希函数通常用于：
#   - Fiat-Shamir transcript
#   - Merkle tree
#   - commitment
#   - proof-of-work / challenge 生成
add_library(whir_thirdparty STATIC
    third_party/blake3/blake3.c
    third_party/blake3/blake3_dispatch.c
    third_party/blake3/blake3_portable.c
    third_party/sha256/sha256.c
    third_party/keccak/keccak.c
)


# ----------------------------------------------------------------------------
# BLAKE3 SIMD 后端
# ----------------------------------------------------------------------------
#
# WHIR_BLAKE3_SIMD:
#   是否启用 BLAKE3 的 SIMD 后端。
#
# WHIR_BLAKE3_AVX512:
#   是否启用 AVX512 后端。
#
# 为什么要单独处理？
#   BLAKE3 的不同 SIMD 源文件需要不同的编译参数：
#       blake3_sse2.c     需要 -msse2
#       blake3_sse41.c    需要 -msse4.1
#       blake3_avx2.c     需要 -mavx2
#       blake3_avx512.c   需要 -mavx512f / -mavx512vl
#
# 如果统一给整个项目加 -mavx2 或 -mavx512，可能会影响可移植性；
# 所以这里使用 set_source_files_properties 只给特定源文件加特定指令集。
#
# 跨平台一致性测试时，可以关闭 SIMD：
#   -DWHIR_BLAKE3_SIMD=OFF
#
# 性能测试时建议开启：
#   -DWHIR_BLAKE3_SIMD=ON
option(WHIR_BLAKE3_SIMD "Enable Blake3 SIMD (SSE4.1/AVX2)" ON)
option(WHIR_BLAKE3_AVX512 "Enable Blake3 AVX512 backend" OFF)

if(WHIR_BLAKE3_SIMD AND (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86"))
    # x86 / x86_64 平台下，加入 SSE2 / SSE4.1 / AVX2 后端源码。
    target_sources(whir_thirdparty PRIVATE
        third_party/blake3/blake3_sse2.c
        third_party/blake3/blake3_sse41.c
        third_party/blake3/blake3_avx2.c
    )

    # AVX512 默认关闭。
    # 原因：
    #   1. 不是所有 CPU 支持 AVX512；
    #   2. 某些 CPU 上 AVX512 可能导致降频；
    #   3. 二进制可移植性会变差。
    if(WHIR_BLAKE3_AVX512)
        target_sources(whir_thirdparty PRIVATE
            third_party/blake3/blake3_avx512.c)
    else()
        target_compile_definitions(whir_thirdparty PRIVATE BLAKE3_NO_AVX512)
    endif()

    # GCC / Clang 下，为不同 SIMD 文件指定对应编译参数。
    # MSVC 的 BLAKE3 SIMD 编译参数处理方式不同，因此这里没有覆盖 MSVC。
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(third_party/blake3/blake3_sse2.c
            PROPERTIES COMPILE_OPTIONS "-msse2")

        set_source_files_properties(third_party/blake3/blake3_sse41.c
            PROPERTIES COMPILE_OPTIONS "-msse4.1")

        set_source_files_properties(third_party/blake3/blake3_avx2.c
            PROPERTIES COMPILE_OPTIONS "-mavx2")

        if(WHIR_BLAKE3_AVX512)
            set_source_files_properties(third_party/blake3/blake3_avx512.c
                PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512vl")
        endif()
    endif()
else()
    # 如果未启用 SIMD，或者当前处理器不是 x86 / x86_64，
    # 就通过宏禁用 BLAKE3 的各类 SIMD 后端。
    #
    # 这样 BLAKE3 会回退到 portable C 实现。
    target_compile_definitions(whir_thirdparty PRIVATE
        BLAKE3_NO_AVX512
        BLAKE3_NO_AVX2
        BLAKE3_NO_SSE41
        BLAKE3_NO_SSE2)
endif()


# 给 whir_thirdparty 暴露第三方库头文件路径。
#
# PUBLIC 表示：
#   whir_thirdparty 自己编译时能包含这些目录；
#   链接 whir_thirdparty 的目标也能继承这些 include 路径。
target_include_directories(whir_thirdparty PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/keccak
)


# ============================================================================
# whir_algebra：header-only 目标
# ============================================================================
#
# INTERFACE library 的特点：
#   1. 不会生成 .a / .lib / .so 文件；
#   2. 不编译源文件；
#   3. 只携带 include 路径、编译宏、链接依赖等“使用要求”。
#
# 这里 whir_algebra 代表 include/ 下的 C++ header-only 代码。
# 其他目标只要 target_link_libraries(... whir_algebra)，就会自动获得：
#   - include 路径
#   - whir_thirdparty 链接依赖
#   - CUDA 相关 include / 宏（如果启用）
add_library(whir_algebra INTERFACE)

# 暴露 include/ 目录。
# 这样代码里可以写：
#   #include <algebra/...>
# 或根据项目布局包含 include 下的头文件。
target_include_directories(whir_algebra INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# whir_algebra 依赖 whir_thirdparty。
# 因为 algebra 里的某些 header 可能会用到 BLAKE3 / SHA256 / Keccak。
target_link_libraries(whir_algebra INTERFACE whir_thirdparty)


# 如果启用了 CUDA：
#   1. 给普通 C++ 编译器暴露 CUDA Toolkit include 路径；
#   2. 给依赖 whir_algebra 的目标定义 WHIR_CUDA；
#   3. 如果开启实验性 NTT，再定义 WHIR_CUDA_EXPERIMENTAL_NTT。
#
# 为什么 C++ 编译器也需要 CUDA include？
#   因为某些 .cpp 或 header 中可能会包含 cuda_runtime.h，
#   或者声明 CUDA dispatch 相关接口。
if(WHIR_CUDA)
    target_include_directories(whir_algebra INTERFACE ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
    target_compile_definitions(whir_algebra INTERFACE WHIR_CUDA)

    if(WHIR_CUDA_EXPERIMENTAL_NTT)
        target_compile_definitions(whir_algebra INTERFACE WHIR_CUDA_EXPERIMENTAL_NTT)
    endif()
endif()


# ============================================================================
# whir_cli：主命令行工具
# ============================================================================
#
# add_executable 会生成一个可执行程序。
# 入口源文件是 main.cpp。
#
# whir_cli 链接 whir_algebra 后，会自动继承：
#   - include/ 头文件路径
#   - whir_thirdparty 静态库
#   - CUDA 宏和 include 路径（如果启用）
add_executable(whir_cli main.cpp)
target_link_libraries(whir_cli PRIVATE whir_algebra)

# 如果启用 CUDA，whir_cli 还需要链接 whir_cuda。
# PRIVATE 表示这个链接关系只对 whir_cli 自己有效，
# 不会继续传播给依赖 whir_cli 的其他目标。
if(WHIR_CUDA)
    target_link_libraries(whir_cli PRIVATE whir_cuda)
endif()


# ============================================================================
# Benchmarks：性能测试程序
# ============================================================================
#
# WHIR_BUILD_BENCHMARKS 控制是否构建 benchmark。
# 默认 ON。
#
# 每个 add_executable 都会生成一个单独的性能测试程序。
# 这些 benchmark 一般用于：
#   1. 测 CPU 实现耗时
#   2. 测 GPU 实现耗时
#   3. 检查 CPU / GPU 输出是否一致
#   4. 对比不同模块的加速比
#
# 如果只想构建库，不想构建 benchmark，可以传：
#   -DWHIR_BUILD_BENCHMARKS=OFF
option(WHIR_BUILD_BENCHMARKS "Build C++ microbenchmarks" ON)

if(WHIR_BUILD_BENCHMARKS)

    # NTT 基准测试。
    add_executable(bench_ntt bench/bench_ntt.cpp)
    target_link_libraries(bench_ntt PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_ntt PRIVATE whir_cuda)
    endif()

    # Reed-Solomon encode 基准测试。
    add_executable(bench_rs_encode bench/bench_rs_encode.cpp)
    target_link_libraries(bench_rs_encode PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_rs_encode PRIVATE whir_cuda)
    endif()

    # RS encode CPU / GPU 或不同实现对比。
    add_executable(bench_rs_encode_compare bench/bench_rs_encode_compare.cpp)
    target_link_libraries(bench_rs_encode_compare PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_rs_encode_compare PRIVATE whir_cuda)
    endif()

    # Merkle tree SHA-256 对比 benchmark。
    add_executable(bench_merkle_sha256_compare bench/bench_merkle_sha256_compare.cpp)
    target_link_libraries(bench_merkle_sha256_compare PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_merkle_sha256_compare PRIVATE whir_cuda)
    endif()

    # Merkle path 生成 / 验证相关对比 benchmark。
    add_executable(bench_merkle_path_compare bench/bench_merkle_path_compare.cpp)
    target_link_libraries(bench_merkle_path_compare PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_merkle_path_compare PRIVATE whir_cuda)
    endif()

    # IRS CUDA 对比 benchmark。
    # IRS 在 WHIR / Reed-Solomon 编码相关流程中常用于编码、承诺或查询路径。
    add_executable(bench_irs_cuda_compare bench/bench_irs_cuda_compare.cpp)
    target_link_libraries(bench_irs_cuda_compare PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_irs_cuda_compare PRIVATE whir_cuda)
    endif()

    # NTT CPU / GPU 对比 benchmark。
    # 你之前跑的 bench_ntt_compare.exe 通常就是这里生成的。
    add_executable(bench_ntt_compare bench/bench_ntt_compare.cpp)
    target_link_libraries(bench_ntt_compare PRIVATE whir_algebra)
    if(WHIR_CUDA)
        target_link_libraries(bench_ntt_compare PRIVATE whir_cuda)
    endif()

endif()


# ============================================================================
# Tests / Dumper：测试与数据导出工具
# ============================================================================
#
# WHIR_BUILD_TESTS 控制是否构建测试。
# 默认 ON。
#
# enable_testing() 会启用 CTest。
# 之后 tests/ 子目录中如果有 add_test(...)，
# 就可以用下面命令运行：
#
#   ctest --test-dir build --output-on-failure
#
# add_subdirectory(tests) 表示进入 tests/ 目录继续读取那里的 CMakeLists.txt。
option(WHIR_BUILD_TESTS "Build C++ tests + dumper" ON)

if(WHIR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
