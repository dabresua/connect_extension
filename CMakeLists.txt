cmake_minimum_required(VERSION 3.9)

# CXX compiler is set by the osquery's toolchain
# set(CMAKE_CXX_COMPILER "clang++")
project("connect_extension")

# Add compile flags to instrument the binaries for coverage
set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -fprofile-instr-generate -fcoverage-mapping -O0 -g")
set(CMAKE_CXX_STANDARD 17)

# Include directories. These are common for the extension and the tests

include_directories(
  main
  runnable
  table
  tests
)

# Build the extension binary
## Configure the source files
set(project_source_files
  main/main.cpp
  table/connect.cpp
)

## Configure the target
addOsqueryExtension(
  "${PROJECT_NAME}"
  ${project_source_files}
  ${platform_source_files}
  ${project_common_include_dirs}
)

# Tests
## Configure the source files
set(common_test_files
  tests/main.cpp
  tests/connect.cpp
  table/connect.cpp
)

## Configure the target for the tests
add_executable(
  "${PROJECT_NAME}_test"
  EXCLUDE_FROM_ALL
  ${common_test_files}
  ${platform_test_files}
  "${CMAKE_CURRENT_SOURCE_DIR}/tests"
  ${project_common_include_dirs}
)

# Third party libraries needed
target_link_libraries("${PROJECT_NAME}_test" PRIVATE
  osquery_sdk_pluginsdk
  osquery_extensions_implthrift
  thirdparty_googletest
)