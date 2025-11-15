#ifndef CLIENT_UDP_TUNNEL_HPP
#define CLIENT_UDP_TUNNEL_HPP

#include "tunnel.hpp"
#include "crypto.hpp"
#include "connection_pool.hpp"
#include <memory>
#include <unordered_map>
#include <netinet/in.h>

class ClientUdpTunnel : public Tunnel
{
private:
    std::string local_addr;
    int local_port;
    std::string remote_addr;
    int remote_port;
    std::string key;

    std::unique_ptr<Crypto> crypto;
    std::unique_ptr<ConnectionPool> pool;
    int listen_fd;
    int epoll_fd;
    std::atomic<uint32_t> next_session_id{1};
    std::unordered_map<uint32_t, sockaddr_in> udp_sessions;

    void setup_listener();
    void handle_udp_data();
    void forward_to_server(uint8_t *data, size_t len, const sockaddr_in &sender);

public:
    ClientUdpTunnel(const std::string &local_addr, int local_port,
                    const std::string &remote_addr, int remote_port,
                    const std::string &key);
    ~ClientUdpTunnel();
    void run() override;
};

#endif