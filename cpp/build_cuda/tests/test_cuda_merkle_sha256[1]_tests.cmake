add_test([=[CudaMerkleSha256.MatchesCpuWitnessNodesAndRoot]=]  /home/wwj/HXD/cpp/build_cuda/tests/test_cuda_merkle_sha256 [==[--gtest_filter=CudaMerkleSha256.MatchesCpuWitnessNodesAndRoot]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CudaMerkleSha256.MatchesCpuWitnessNodesAndRoot]=]  PROPERTIES WORKING_DIRECTORY /home/wwj/HXD/cpp/build_cuda/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  test_cuda_merkle_sha256_TESTS CudaMerkleSha256.MatchesCpuWitnessNodesAndRoot)
