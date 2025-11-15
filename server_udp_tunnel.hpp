#ifndef SERVER_UDP_TUNNEL_HPP
#define SERVER_UDP_TUNNEL_HPP

#include "tunnel.hpp"
#include "crypto.hpp"
#include "session_store.hpp"
#include <memory>
#include <unordered_map>
#include <netinet/in.h>

class ServerUdpTunnel : public Tunnel
{
private:
    std::string local_addr;
    int local_port;
    std::string target_addr;
    int target_port;
    std::string key;

    std::unique_ptr<Crypto> crypto;
    std::unique_ptr<SessionStore> session_store;
    int listen_fd;
    int epoll_fd;
    std::unordered_map<uint32_t, sockaddr_in> udp_sessions;

    void setup_listener();
    void handle_udp_data();
    void forward_to_target(uint8_t *data, size_t len, const sockaddr_in &sender);

public:
    ServerUdpTunnel(const std::string &local_addr, int local_port,
                    const std::string &target_addr, int target_port,
                    const std::string &key);
    ~ServerUdpTunnel();
    void run() override;
};

#endif