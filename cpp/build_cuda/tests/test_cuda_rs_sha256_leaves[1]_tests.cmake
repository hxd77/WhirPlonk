add_test([=[CudaRsSha256Leaves.MatchesCpuSha2CommitLeaves]=]  /home/wwj/HXD/cpp/build_cuda/tests/test_cuda_rs_sha256_leaves [==[--gtest_filter=CudaRsSha256Leaves.MatchesCpuSha2CommitLeaves]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CudaRsSha256Leaves.MatchesCpuSha2CommitLeaves]=]  PROPERTIES WORKING_DIRECTORY /home/wwj/HXD/cpp/build_cuda/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  test_cuda_rs_sha256_leaves_TESTS CudaRsSha256Leaves.MatchesCpuSha2CommitLeaves)
