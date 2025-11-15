#ifndef CLIENT_TCP_TUNNEL_HPP
#define CLIENT_TCP_TUNNEL_HPP

#include <memory>
#include <unordered_map>
#include <netinet/in.h>
#include "tunnel.hpp"
#include "crypto/crypto.hpp"
#include "connection_pool.hpp"

class ClientTcpTunnel : public Tunnel
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
    std::unordered_map<int, uint32_t> client_sessions;
    std::unordered_map<uint32_t, int> session_to_client;

    void setup_listener();
    void setup_response_listener();
    void handle_new_connection();
    void handle_response_connection();
    void handle_client_data(int fd);
    void handle_response_data(int fd);
    void forward_request_to_server(int client_fd, uint8_t *data, size_t len);
    void forward_response_to_client(int response_fd, uint8_t *data, size_t len);

public:
    ClientTcpTunnel(const std::string &local_addr, int local_port,
                    const std::string &remote_addr, int remote_port,
                    const std::string &response_addr, int response_port,
                    std::shared_ptr<Crypto> crypto);
    ~ClientTcpTunnel();
    void run() override;
};

#endif