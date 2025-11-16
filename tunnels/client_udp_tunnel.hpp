#ifndef CLIENT_UDP_TUNNEL_HPP
#define CLIENT_UDP_TUNNEL_HPP

#include <memory>
#include <unordered_map>
#include <netinet/in.h>
#include "tunnel.hpp"
#include "crypto/crypto.hpp"
#include "connection_pool.hpp"

class ClientUdpTunnel : public Tunnel
{
private:
    std::string local_addr;
    int local_port;
    std::string response_addr;
    int response_port;
    std::shared_ptr<Crypto> crypto;

    std::unique_ptr<ConnectionPool> request_pool;
    int listen_fd;
    int response_listen_fd;
    int epoll_fd;
    std::atomic<uint32_t> next_session_id{1};
    std::unordered_map<std::string, uint32_t> source_addr_to_session_id;
    std::unordered_map<uint32_t, std::pair<sockaddr_storage, socklen_t>> session_id_to_source_addr;

    void setup_listener();
    void setup_response_listener();
    void handle_request_data();
    void forward_request_to_server(uint8_t *data, size_t len, const sockaddr_storage &source_addr, socklen_t source_addr_len);
    void handle_response_data();
    void forward_response_to_source(uint8_t *data, size_t len);
    std::string addr_to_string(const sockaddr_storage &addr);

public:
    ClientUdpTunnel(const std::string &local_addr, int local_port,
                    const std::string &remote_addr, int remote_port,
                    const std::string &response_addr, int response_port,
                    std::shared_ptr<Crypto> crypto);
    ~ClientUdpTunnel();
    void run() override;
};

#endif