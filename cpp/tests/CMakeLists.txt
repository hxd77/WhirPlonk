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

add_executable(dump_whir dump_whir.cpp)
target_link_libraries(dump_whir PRIVATE whir_algebra)

# ============================================================
# demo_irs_commit — IRS 承诺协议分步演示 (教学用途)
# ============================================================
add_executable(demo_irs_commit ../demo/demo_irs_commit.cpp)
target_link_libraries(demo_irs_commit PRIVATE whir_algebra)

add_executable(demo_open_verify ../demo/demo_open_verify.cpp)
target_link_libraries(demo_open_verify PRIVATE whir_algebra)

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
gtest_discover_tests(test_protocols)
