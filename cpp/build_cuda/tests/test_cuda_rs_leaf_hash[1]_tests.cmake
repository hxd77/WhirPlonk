add_test([=[CudaRsLeafHash.GpuBytesCpuBlake3MatchesCpuCommitLeaves]=]  /home/wwj/HXD/cpp/build_cuda/tests/test_cuda_rs_leaf_hash [==[--gtest_filter=CudaRsLeafHash.GpuBytesCpuBlake3MatchesCpuCommitLeaves]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CudaRsLeafHash.GpuBytesCpuBlake3MatchesCpuCommitLeaves]=]  PROPERTIES WORKING_DIRECTORY /home/wwj/HXD/cpp/build_cuda/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  test_cuda_rs_leaf_hash_TESTS CudaRsLeafHash.GpuBytesCpuBlake3MatchesCpuCommitLeaves)
