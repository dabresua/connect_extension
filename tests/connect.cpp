#include <gtest/gtest.h>

#include <connect.h>

namespace connect_extension {

class ConnectTest : public ::testing::Test {
private:
  Connect c;

public:
  ConnectTest() : c() {}

  void TestBody() override {}

  bool connect(const std::string & serverIP, int port)
  {
    return c.connect(serverIP, port);
  }

  std::vector<std::string> getServerIP(const std::string & serverName)
  {
    return c.getServerIP(serverName);
  }
};

typedef struct test_t {
  std::string ip;
  int port;
  bool result;
} test_t;

TEST(ConnectTest, ip) {
  ConnectTest ct;
  std::vector<std::string> other_test = ct.getServerIP("osquery.io");

  test_t test[] = {
    {"8.8.8.8", 53, true},
    {"8.8.4.4", 53, true},
    {"1.2.3.4", 5678, false},
  };

  for (size_t i = 0; i < other_test.size(); i++)
  {
    bool b = ct.connect(other_test[i], 80);
    EXPECT_EQ(b, true);
  }

  for (size_t i = 0; i < (sizeof(test)/sizeof(test_t)); i++) {
    bool b = ct.connect(test[i].ip, test[i].port);
    EXPECT_EQ(b, test[i].result);
  }
}

} // connect_extension