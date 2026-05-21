add_test([=[CudaRsSha256Merkle.MatchesCpuMerkleRoot]=]  /home/wwj/HXD/cpp/build_cuda/tests/test_cuda_rs_sha256_merkle [==[--gtest_filter=CudaRsSha256Merkle.MatchesCpuMerkleRoot]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CudaRsSha256Merkle.MatchesCpuMerkleRoot]=]  PROPERTIES WORKING_DIRECTORY /home/wwj/HXD/cpp/build_cuda/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  test_cuda_rs_sha256_merkle_TESTS CudaRsSha256Merkle.MatchesCpuMerkleRoot)
