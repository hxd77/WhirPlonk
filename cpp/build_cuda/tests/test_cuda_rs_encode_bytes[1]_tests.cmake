add_test([=[CudaRsEncodeBytes.MatchesCpuBytes]=]  /home/wwj/HXD/cpp/build_cuda/tests/test_cuda_rs_encode_bytes [==[--gtest_filter=CudaRsEncodeBytes.MatchesCpuBytes]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CudaRsEncodeBytes.MatchesCpuBytes]=]  PROPERTIES WORKING_DIRECTORY /home/wwj/HXD/cpp/build_cuda/tests SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  test_cuda_rs_encode_bytes_TESTS CudaRsEncodeBytes.MatchesCpuBytes)
