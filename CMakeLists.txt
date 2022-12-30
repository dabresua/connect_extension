project("connect_extension")

# Include directories. These are common for the extension and the tests

include_directories(
  main
  runnable
  table
  tests
)

set(project_common_include_dirs
  "${CMAKE_CURRENT_SOURCE_DIR}/main"
  "${CMAKE_CURRENT_SOURCE_DIR}/runnable"
  "${CMAKE_CURRENT_SOURCE_DIR}/table"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests"
)

# Build the extension binary
## Configure the source files
set(project_source_files
  main/main.cpp
  table/connect.cpp
  #runnable/runnable_example.cpp
)

### Source files if there are differences between OS
if(WIN32)
  set(platform_source_files
  )
else()
  set(platform_source_files
  )
endif()

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

### Source files if there are differences between OS
if(WIN32)
  set(platform_test_files
  )
else()
  set(platform_test_files
  )
endif()

## Coverage report extra configuration
if(ENABLE_COVERAGE)
  message("Enabling coverage")
  # set compiler flags
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
  set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
  # find required tools
  find_program(GCOVR gcovr REQUIRED)
endif()

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

# Coverage extra steps
if(ENABLE_COVERAGE)
  add_link_options("--coverage")
  include(GoogleTest)
  gtest_discover_tests("${PROJECT_NAME}_test")
endif()