#include <gtest/gtest.h>
#include <debug.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry.h>
#include <osquery/database/database.h>

using namespace osquery;

GTEST_API_ int main(int argc, char** argv) {
  // Init google test environment
  testing::InitGoogleTest(&argc, argv);

  // Init osquery database and plugins
  osquery::platformSetup();
  osquery::registryAndPluginInit();
  osquery::initDatabasePluginForTesting();

  // Run all registered tests
  auto r = RUN_ALL_TESTS();
  return r;
}