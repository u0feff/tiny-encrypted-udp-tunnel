#ifndef NETWORK_UTILS_HPP
#define NETWORK_UTILS_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>

// Detect if an address string is IPv6
inline bool is_ipv6(const std::string &addr)
{
    struct in6_addr result;
    return inet_pton(AF_INET6, addr.c_str(), &result) == 1;
}

// Get the appropriate address family for a given address string
inline int get_address_family(const std::string &addr)
{
    return is_ipv6(addr) ? AF_INET6 : AF_INET;
}

// Setup sockaddr_storage for a given address and port
inline void setup_sockaddr(sockaddr_storage &addr_storage, socklen_t &addr_len,
                           const std::string &addr, int port)
{
    memset(&addr_storage, 0, sizeof(addr_storage));

    if (is_ipv6(addr))
    {
        sockaddr_in6 *addr6 = (sockaddr_in6 *)&addr_storage;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
        inet_pton(AF_INET6, addr.c_str(), &addr6->sin6_addr);
        addr_len = sizeof(sockaddr_in6);
    }
    else
    {
        sockaddr_in *addr4 = (sockaddr_in *)&addr_storage;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        inet_pton(AF_INET, addr.c_str(), &addr4->sin_addr);
        addr_len = sizeof(sockaddr_in);
    }
}

#endif
