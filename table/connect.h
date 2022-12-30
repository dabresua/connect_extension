/**
 * @file connect.h
 * @author your name (d.breton.suarez@gmail.com)
 * @brief Defines a table with a very basic connect functionality
 * @version 0.1
 * @date 2022-12-25
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#pragma once

// Include the SDK and helpers
#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#ifdef _WIN32
#include <WinSock2.h>
#else /* _WIN32 */
#include <sys/socket.h>
#endif /* _WIN32 */

#include <chrono>

namespace connect_extension
{
class Connect : public osquery::TablePlugin {
public:
  /**
   * @brief Construct a new Connect object
   * 
   */
  Connect();

  /**
   * @brief Destroy the Connect object
   * 
   */
  ~Connect();

  /**
   * @brief returns the list of columns of the table
   * 
   * @return osquery::TableColumns list of columns
   */
  osquery::TableColumns columns() const override;

  /**
   * @brief generate a response given the request
   * 
   * @param request query request
   * @return osquery::TableRows query response
   */
  osquery::TableRows generate(osquery::QueryContext & request) override;
private:
  std::string myIP; /**< The ip of the machine */
  std::chrono::steady_clock::time_point start; /**< Connect start */
  std::chrono::steady_clock::time_point end; /**< Connect end */
  /**
   * @brief Checks a TCP connection
   * 
   * @param serverIP ip of the server to perform the connect against
   * @param port port of the server to perform the connect against
   * @param protocol specifies the connection protocol
   * @return true the server is reachable
   * @return false the server is unreachable
   */
  bool connect(const std::string & serverIP, int port);

  /**
   * @brief Get an IP given the server name
   * 
   * @param serverName the name of the server (i.e. google.com)
   * @return std::string resolved IP (i.e. 142.250.185.14)
   */
  std::vector<std::string> getServerIP(const std::string & serverName);

  /**
   * @brief Get the Server Name given the IP
   * 
   * @param ip The IP of the server
   * @return std::string the resolved server name
   */
  std::string getServerName(const std::string & ip);

  friend class ConnectTest;
};

} // namespace connect_extension