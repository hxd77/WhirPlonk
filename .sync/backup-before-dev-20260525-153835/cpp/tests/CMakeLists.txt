# cpp/tests: 跨语言对拍的 dumper, 以及 protocols 单元测试。
#
# 父级 cpp/CMakeLists.txt 通过 add_subdirectory(tests) 引入这里。
# 这里依赖 whir_algebra (INTERFACE), GoogleTest 通过 FetchContent 拉取。

# ============================================================
# dump_golden_algebra (保留完整版, 向后兼容)
# ============================================================
add_executable(dump_golden_algebra dump_golden_algebra.cpp)
target_link_libraries(dump_golden_algebra PRIVATE whir_algebra)

# ============================================================
# 拆分版 golden dumpers — 每个独立可运行, 对应 examples/dump_*.rs
# ============================================================
add_executable(dump_algebra_fields dump_algebra_fields.cpp)
target_link_libraries(dump_algebra_fields PRIVATE whir_algebra)

add_executable(dump_algebra_utils dump_algebra_utils.cpp)
target_link_libraries(dump_algebra_utils PRIVATE whir_algebra)

add_executable(dump_algebra_ntt dump_algebra_ntt.cpp)
target_link_libraries(dump_algebra_ntt PRIVATE whir_algebra)

add_executable(dump_hash dump_hash.cpp)
target_link_libraries(dump_hash PRIVATE whir_algebra)

add_executable(dump_merkle_tree dump_merkle_tree.cpp)
target_link_libraries(dump_merkle_tree PRIVATE whir_algebra)

add_executable(dump_pow dump_pow.cpp)
target_link_libraries(dump_pow PRIVATE whir_algebra)

add_executable(dump_matrix_commit dump_matrix_commit.cpp)
target_link_libraries(dump_matrix_commit PRIVATE whir_algebra)

add_executable(dump_irs_commit dump_irs_commit.cpp)
target_link_libraries(dump_irs_commit PRIVATE whir_algebra)

add_executable(dump_sumcheck dump_sumcheck.cpp)
target_link_libraries(dump_sumcheck PRIVATE whir_algebra)

add_executable(dump_transcript dump_transcript.cpp)
target_link_libraries(dump_transcript PRIVATE whir_algebra)

add_executable(dump_rng dump_rng.cpp)
target_link_libraries(dump_rng PRIVATE whir_algebra)

add_executable(dump_whir dump_whir.cpp)
target_link_libraries(dump_whir PRIVATE whir_algebra)

add_executable(dump_whir_zk dump_whir_zk.cpp)
target_link_libraries(dump_whir_zk PRIVATE whir_algebra)

# ============================================================
# demo_irs_commit — IRS 承诺协议分步演示 (教学用途)
# ============================================================
add_executable(demo_irs_commit ../demo/demo_irs_commit.cpp)
target_link_libraries(demo_irs_commit PRIVATE whir_algebra)

add_executable(demo_open_verify ../demo/demo_open_verify.cpp)
target_link_libraries(demo_open_verify PRIVATE whir_algebra)

# CUDA 构建时, 所有 dump/demo 目标也需链接 whir_cuda (NTT 头文件中有 CUDA dispatch)
if(WHIR_CUDA)
    foreach(_dump_target
        dump_golden_algebra
        dump_algebra_fields dump_algebra_utils dump_algebra_ntt
        dump_hash dump_merkle_tree dump_pow dump_matrix_commit
        dump_irs_commit dump_sumcheck dump_transcript dump_rng
        dump_whir dump_whir_zk
        demo_irs_commit demo_open_verify
    )
        target_link_libraries(${_dump_target} PRIVATE whir_cuda)
    endforeach()
endif()

# ============================================================
# GoogleTest (通过 FetchContent, 配置时下载)
# ============================================================
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
# MSVC 才需要 force shared CRT, 其他 toolchain 无副作用。
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# 不要让 GTest 的 install rule 污染上层项目的 install。
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# ============================================================
# test_protocols: 覆盖 challenge_indices / matrix_commit / proof_of_work / merkle_tree
# ============================================================
add_executable(test_protocols test_protocols.cpp)
target_link_libraries(test_protocols PRIVATE whir_algebra GTest::gtest_main)
if(WHIR_CUDA)
    target_link_libraries(test_protocols PRIVATE whir_cuda)
endif()
gtest_discover_tests(test_protocols)

if(WHIR_CUDA)
    add_executable(test_cuda_ntt test_cuda_ntt.cpp)
    target_link_libraries(test_cuda_ntt PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_ntt)

    add_executable(test_cuda_rs_encode test_cuda_rs_encode.cpp)
    target_link_libraries(test_cuda_rs_encode PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_rs_encode)

    add_executable(test_cuda_rs_encode_bytes test_cuda_rs_encode_bytes.cpp)
    target_link_libraries(test_cuda_rs_encode_bytes PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_rs_encode_bytes)

    add_executable(test_cuda_rs_leaf_hash test_cuda_rs_leaf_hash.cpp)
    target_link_libraries(test_cuda_rs_leaf_hash PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_rs_leaf_hash)

    add_executable(test_cuda_rs_sha256_leaves test_cuda_rs_sha256_leaves.cpp)
    target_link_libraries(test_cuda_rs_sha256_leaves PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_rs_sha256_leaves)

    add_executable(test_cuda_merkle_sha256 test_cuda_merkle_sha256.cpp)
    target_link_libraries(test_cuda_merkle_sha256 PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_merkle_sha256)

    add_executable(test_cuda_merkle_path test_cuda_merkle_path.cpp)
    target_link_libraries(test_cuda_merkle_path PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_merkle_path)

    add_executable(test_cuda_irs_commit test_cuda_irs_commit.cpp)
    target_link_libraries(test_cuda_irs_commit PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_irs_commit)

    add_executable(test_cuda_rs_sha256_merkle test_cuda_rs_sha256_merkle.cpp)
    target_link_libraries(test_cuda_rs_sha256_merkle PRIVATE whir_algebra whir_cuda GTest::gtest_main)
    gtest_discover_tests(test_cuda_rs_sha256_merkle)
endif()
