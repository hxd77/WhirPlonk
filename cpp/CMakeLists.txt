# whir C++ 翻译的根 CMake。
#
# 目标:
#   whir_thirdparty (STATIC)  — vendored BLAKE3 portable + Brad Conte SHA-256
#   whir_algebra    (INTERFACE) — header-only, 把 include 路径暴露出去, 顺带 link 上面那个静态库
#
# 子目录:
#   tests/   — dump_golden_algebra 等 cpp dumper / 单元测试

cmake_minimum_required(VERSION 3.16)
project(whir_cpp LANGUAGES C CXX)

# 顶层调用时给个默认 build type, 避免 MSVC 单 config 拿不到优化的 Release。
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 本地 CPU 优化 (g++/clang++ 自动启用 AVX2/AVX512/BMI 等指令)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-march=native)
endif()

# ---- OpenMP (多线程加速 CPU) ----
option(WHIR_OPENMP "Enable OpenMP multi-threading" ON)
if(WHIR_OPENMP)
    find_package(OpenMP REQUIRED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    message(STATUS "OpenMP enabled")
else()
    message(STATUS "OpenMP disabled — single-threaded build")
endif()

# ---- CUDA (GPU 加速 NTT + 编码) ----
# 需要 nvcc + CUDA Toolkit ≥ 11.0, 架构 ≥ sm_75
# Linux 启用: cmake -DWHIR_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=89
option(WHIR_CUDA "Enable CUDA GPU acceleration" OFF)
if(WHIR_CUDA)
    enable_language(CUDA)
    set(CMAKE_CUDA_STANDARD 17)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
    # 默认目标 4090 (sm_89), 可通过 -DCMAKE_CUDA_ARCHITECTURES=XX 覆盖
    if(NOT CMAKE_CUDA_ARCHITECTURES)
        set(CMAKE_CUDA_ARCHITECTURES 89)
    endif()
    add_library(whir_cuda STATIC cuda/cuda_ntt.cu)
    target_include_directories(whir_cuda PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(whir_cuda PUBLIC WHIR_CUDA)
    message(STATUS "CUDA enabled (GPU NTT + encoding, arch=sm_${CMAKE_CUDA_ARCHITECTURES})")
else()
    message(STATUS "CUDA disabled — CPU-only build")
endif()

if(MSVC)
    add_compile_options(/utf-8)
endif()

# ============================================================
# whir_thirdparty: vendored C 依赖
# ============================================================
add_library(whir_thirdparty STATIC
    third_party/blake3/blake3.c
    third_party/blake3/blake3_dispatch.c
    third_party/blake3/blake3_portable.c
    third_party/sha256/sha256.c
    third_party/keccak/keccak.c
)

# blake3 SIMD 可根据目标平台启用 (SSE4.1/AVX2 可大幅加速哈希)
# 跨平台对拍时全关; 性能测试时全开。
option(WHIR_BLAKE3_SIMD "Enable Blake3 SIMD (SSE4.1/AVX2)" ON)
option(WHIR_BLAKE3_AVX512 "Enable Blake3 AVX512 backend" OFF)
if(WHIR_BLAKE3_SIMD AND (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86"))
    target_sources(whir_thirdparty PRIVATE
        third_party/blake3/blake3_sse2.c
        third_party/blake3/blake3_sse41.c
        third_party/blake3/blake3_avx2.c
    )
    if(WHIR_BLAKE3_AVX512)
        target_sources(whir_thirdparty PRIVATE
            third_party/blake3/blake3_avx512.c)
    else()
        target_compile_definitions(whir_thirdparty PRIVATE BLAKE3_NO_AVX512)
    endif()

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
    target_compile_definitions(whir_thirdparty PRIVATE
        BLAKE3_NO_AVX512
        BLAKE3_NO_AVX2
        BLAKE3_NO_SSE41
        BLAKE3_NO_SSE2)
endif()

target_include_directories(whir_thirdparty PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sha256
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/keccak
)

# ============================================================
# whir_algebra: header-only
# ============================================================
add_library(whir_algebra INTERFACE)
target_include_directories(whir_algebra INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(whir_algebra INTERFACE whir_thirdparty)
# g++ 编译 .cpp 时需 CUDA runtime 头文件 (WHIR_CUDA 激活 GPU dispatch 路径)
if(WHIR_CUDA)
    target_include_directories(whir_algebra INTERFACE ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
endif()

# ============================================================
# main — WHIR CLI 工具
# ============================================================
add_executable(whir_cli main.cpp)
target_link_libraries(whir_cli PRIVATE whir_algebra)
if(WHIR_CUDA)
    target_link_libraries(whir_cli PRIVATE whir_cuda)
endif()

# ============================================================
# 测试 / dumper
# ============================================================
option(WHIR_BUILD_TESTS "Build C++ tests + dumper" ON)
if(WHIR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
