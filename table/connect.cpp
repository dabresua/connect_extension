#include <connect.h>

#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>

#ifdef _WIN32
#include <ws2tcpip.h>
#include <sys/types.h>
#else /* _WIN32 */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif /* _WIN32 */

using namespace osquery;

namespace connect_extension
{

Connect::Connect() : myIP("0.0.0.0")
{
  #ifdef _WIN32
  WSADATA data;
  if (WSAStartup (MAKEWORD(1, 1), &data) != 0) {
    printf("Can not initialize Winsock\n");
    exit(1);
  }
  #endif /* _WIN32 */
}

Connect::~Connect()
{
  #ifdef _WIN32
  WSACleanup();
  #endif /* _WIN32 */
}

TableColumns Connect::columns() const
{
  return {
    std::make_tuple("my_ip",       TEXT_TYPE,    ColumnOptions::DEFAULT),
    std::make_tuple("server_name", TEXT_TYPE,    ColumnOptions::DEFAULT),
    std::make_tuple("server_ip",   TEXT_TYPE,    ColumnOptions::DEFAULT),
    std::make_tuple("server_port", INTEGER_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("reachable",   INTEGER_TYPE, ColumnOptions::DEFAULT),
    std::make_tuple("connect_time",BIGINT_TYPE,  ColumnOptions::DEFAULT),
  };
}

std::vector<std::string> Connect::getServerIP(const std::string & serverName)
{
  struct hostent *remoteHost;
  std::vector<std::string> ret;

  remoteHost = gethostbyname(serverName.c_str());
  if (NULL == remoteHost) {
    switch (h_errno)
    {
    case HOST_NOT_FOUND:
      printf("The host was not found\n");
      break;
    case NO_ADDRESS:
      printf("The name is valid but it has no address\n");
      break;
    case NO_RECOVERY:
      printf("A non-recoverable name server error occurred\n");
      break;
    case TRY_AGAIN:
      printf("The name server is temporarily unavailable\n");
      break;
    default:
      printf("Some other error has ocurred\n");
      break;
    }
  } else {
    printf("--- Remote host info ---\n");
    printf("\tOfficial name: %s\n", remoteHost->h_name);
    printf("\tAddress type: ");
    switch (remoteHost->h_addrtype) {
    case AF_INET:
    {
      printf("AF_INET\n");
      int i = 0;
      struct in_addr addr;
      while (remoteHost->h_addr_list[i] != 0) {
        addr.s_addr = *(u_long *) remoteHost->h_addr_list[i++];
        ret.push_back(inet_ntoa(addr));
        printf("\tIPv4 Address #%d: %s\n", i, ret.back().c_str());
      }
      break;
    }
    case AF_INET6:
      printf("AF_INET6\n");
      printf("\tRemotehost is an IPv6 address and it's not supported yet\n");
      break;
    #ifdef _WIN32
    case AF_NETBIOS:
      printf("AF_NETBIOS\n");
      printf("\tRemotehost is an NetBios address and it's not supported yet\n");
      break;
    #endif /* _WIN32 */
    default:
      printf(" %d\n", remoteHost->h_addrtype);
      break;
    }
  }
  return ret;
}

std::string Connect::getServerName(const std::string & ip)
{
    struct sockaddr_in addr;
    char buf[NI_MAXHOST];
 
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    socklen_t len = sizeof(struct sockaddr_in);
 
    if (getnameinfo((struct sockaddr *)&addr, len, buf, sizeof(buf), NULL, 0, 
                    NI_NAMEREQD)) {
      printf("Could not resolve reverse lookup of hostname\n");
      return "";
    }
    return std::string(buf);
}

TableRows Connect::generate(QueryContext& request)
{
  TableRows results;

  auto names = request.constraints["server_name"].getAll(EQUALS);
  auto ips = request.constraints["server_ip"].getAll(EQUALS);
  auto ports = request.constraints["server_port"].getAll(EQUALS);
  if (ports.size() > 1 || names.size() > 1 || ips.size() > 1 ||
      (names.size() > 0 && ips.size() > 0) ||
      (ips.size() > 0 && names.size() > 0)
      ) {
    LOG(WARNING) << "Only accepts one server and one port";
    return results;
  }

  std::vector<std::string> serverIPs;
  std::string serverName;
  if (ips.size() > 0) {
    serverIPs.push_back(*ips.begin());
    serverName = getServerName(*ips.begin());
  } else {
    serverIPs = getServerIP(*names.begin());
    serverName = *names.begin();
  }

  std::string _serverPort = *ports.begin();
  int serverPort;
  {
    std::stringstream ss;
    ss << _serverPort;
    ss >> serverPort;
  }

  for (const std::string & serverIP : serverIPs)
  {
    printf("Trying to connect server %s, port %d\n", serverIP.c_str(), 
           serverPort);
    bool reachable = connect(serverIP, serverPort);
    printf("The server is %s\n", reachable ? "reachable" : "unavailable");

    auto r = make_table_row();
    r["my_ip"] = myIP;
    r["server_name"] = serverName;
    r["server_ip"] = serverIP;
    r["server_port"] = INTEGER(serverPort);
    r["reachable"] = INTEGER(reachable);
    r["connect_time"] = reachable ? 
      UNSIGNED_BIGINT(
        std::chrono::duration_cast<std::chrono::microseconds>(end - start)
          .count()) :
      UNSIGNED_BIGINT(-1);

    results.push_back(r);
  }

  if (results.size() == 0) {
    auto r = make_table_row();
    r["my_ip"] = myIP;
    r["server_name"] = serverName;
    r["server_ip"] = "";
    r["server_port"] = INTEGER(serverPort);
    r["reachable"] = INTEGER(false);
    r["connect_time"] = UNSIGNED_BIGINT(-1);
    results.push_back(r);
  }
  return results;
}

bool Connect::connect(const std::string & serverIP, int port)
{
  struct sockaddr_in serv;
  // SOCK_DGRAM = UDP, SOCK_STREAM = TCP
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    printf("Cannot create socket\n");
    myIP = "0.0.0.0";
    return false;
  }

  struct timeval timeout{10, 0};
  if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, 
                 sizeof(struct timeval)) < 0) {
    printf("Cannot configure socket\n");
    myIP = "0.0.0.0";
    return false;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, 
                 sizeof(struct timeval)) < 0) {
    printf("Cannot configure socket\n");
    myIP = "0.0.0.0";
    return false;
  }

  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(serverIP.c_str());
  serv.sin_port = htons(port);

  start = std::chrono::steady_clock::now();
  int n = ::connect(sockfd, (const struct sockaddr*)&serv, sizeof(serv));
  if (n < 0) {
    printf("Cannot connect\n");
    myIP = "0.0.0.0";
    return false;
  }
  end = std::chrono::steady_clock::now();

  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  if (getsockname(sockfd, (struct sockaddr*)&name, &namelen) < 0) {
    printf("Cannot get socket name\n");
    myIP = "0.0.0.0";
    return false;
  }

  char buffer[80];
  const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 80);
  if (NULL == p) {
    printf("Cannot get my own ip\n");
    myIP = "0.0.0.0";
    return false;
  }
  myIP = buffer;

  #ifndef _WIN32
  close(sockfd);
  #endif /* _WIN32 */

  return true;
}

} // namespace connect_extension
