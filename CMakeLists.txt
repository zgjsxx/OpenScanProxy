cmake_minimum_required(VERSION 3.16)
project(OpenScanProxy VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(openscanproxy
  cmd/openscanproxy/main.cpp
  src/core/util.cpp
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
)

target_include_directories(openscanproxy PRIVATE include)
target_link_libraries(openscanproxy PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)

set(ADMIN_STATIC_DIR_DEFAULT "${CMAKE_SOURCE_DIR}/web/dist" CACHE PATH "Default admin static asset directory")
message(STATUS "Admin static assets directory: ${ADMIN_STATIC_DIR_DEFAULT}")
