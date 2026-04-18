cmake_minimum_required(VERSION 3.16)
project(OpenScanProxy VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC: 使用 UTF-8 源文件编码
if(MSVC)
  add_compile_options(/utf-8)
endif()

find_package(OpenSSL REQUIRED)
include(CTest)

add_executable(openscanproxy
  cmd/openscanproxy/main.cpp
  src/core/util.cpp
  src/core/logger.cpp
  src/config/config.cpp
  src/http/http_message.cpp
  src/extractor/extractor.cpp
  src/scanner/mock_scanner.cpp
  src/scanner/clamav_scanner.cpp
  src/policy/policy.cpp
  src/audit/audit.cpp
  src/stats/stats.cpp
  src/tlsmitm/tls_mitm.cpp
  src/proxy/proxy_server.cpp
  src/admin/admin_server.cpp
  src/auth/auth_portal_server.cpp
)

target_include_directories(openscanproxy PRIVATE include)
target_link_libraries(openscanproxy PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)

set(ADMIN_STATIC_DIR_DEFAULT "${CMAKE_SOURCE_DIR}/web/dist" CACHE PATH "Default admin static asset directory")
message(STATUS "Admin static assets directory: ${ADMIN_STATIC_DIR_DEFAULT}")

if(BUILD_TESTING)
  add_executable(http_message_test
    tests/http_message_test.cpp
    src/core/util.cpp
    src/http/http_message.cpp
  )
  target_include_directories(http_message_test PRIVATE include)
  target_link_libraries(http_message_test PRIVATE OpenSSL::Crypto)

  add_executable(policy_test
    tests/policy_test.cpp
    src/core/util.cpp
    src/policy/policy.cpp
  )
  target_include_directories(policy_test PRIVATE include)
  target_link_libraries(policy_test PRIVATE OpenSSL::Crypto)

  add_executable(http_protocol_test
    tests/http_protocol_test.cpp
    src/core/util.cpp
    src/http/http_message.cpp
  )
  target_include_directories(http_protocol_test PRIVATE include)
  target_link_libraries(http_protocol_test PRIVATE OpenSSL::Crypto)

  add_executable(config_test
    tests/config_test.cpp
    src/core/util.cpp
    src/policy/policy.cpp
    src/config/config.cpp
  )
  target_include_directories(config_test PRIVATE include)
  target_link_libraries(config_test PRIVATE OpenSSL::Crypto)

  add_executable(stats_test
    tests/stats_test.cpp
    src/stats/stats.cpp
  )
  target_include_directories(stats_test PRIVATE include)

  add_executable(util_test
    tests/util_test.cpp
    src/core/util.cpp
  )
  target_include_directories(util_test PRIVATE include)
  target_link_libraries(util_test PRIVATE OpenSSL::Crypto)

  add_executable(extractor_test
    tests/extractor_test.cpp
    src/core/util.cpp
    src/http/http_message.cpp
    src/extractor/extractor.cpp
  )
  target_include_directories(extractor_test PRIVATE include)
  target_link_libraries(extractor_test PRIVATE OpenSSL::Crypto)

  add_test(NAME http_message_test COMMAND http_message_test)
  add_test(NAME http_protocol_test COMMAND http_protocol_test)
  add_test(NAME policy_test COMMAND policy_test)
  add_test(NAME config_test COMMAND config_test)
  add_test(NAME stats_test COMMAND stats_test)
  add_test(NAME util_test COMMAND util_test)
  add_test(NAME extractor_test COMMAND extractor_test)

  # 集成测试：启动代理 + Mock 上游，验证端到端流程
  # 仅在 POSIX 平台（Linux/macOS）构建，因为依赖的源文件使用了 POSIX socket API
  if(NOT MSVC)
    add_executable(integration_test
      tests/integration_test.cpp
      src/core/util.cpp
      src/core/logger.cpp
      src/config/config.cpp
      src/http/http_message.cpp
      src/extractor/extractor.cpp
      src/scanner/mock_scanner.cpp
      src/policy/policy.cpp
      src/audit/audit.cpp
      src/stats/stats.cpp
      src/tlsmitm/tls_mitm.cpp
      src/proxy/proxy_server.cpp
      src/admin/admin_server.cpp
      src/auth/auth_portal_server.cpp
    )
    target_include_directories(integration_test PRIVATE include)
    target_link_libraries(integration_test PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
    add_test(NAME integration_test COMMAND integration_test)
  endif()

  set_tests_properties(http_message_test http_protocol_test policy_test config_test stats_test util_test extractor_test PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )
  if(NOT MSVC)
    set_tests_properties(integration_test PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
  endif()
endif()


