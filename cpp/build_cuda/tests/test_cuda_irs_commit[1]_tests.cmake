add_test([=[CudaIrsCommit.Sha2CommitOpenVerifyUsesGpuMerklePath]=]  /home/wwj/HXD/cpp/build_cuda/tests/test_cuda_irs_commit [==[--gtest_filter=CudaIrsCommit.Sha2CommitOpenVerifyUsesGpuMerklePath]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CudaIrsCommit.Sha2CommitOpenVerifyUsesGpuMerklePath]=]  PROPERTIES WORKING_DIRECTORY /home/wwj/HXD/cpp/build_cuda/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  test_cuda_irs_commit_TESTS CudaIrsCommit.Sha2CommitOpenVerifyUsesGpuMerklePath)
