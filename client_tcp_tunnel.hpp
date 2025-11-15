#ifndef CLIENT_TCP_TUNNEL_HPP
#define CLIENT_TCP_TUNNEL_HPP

#include "tunnel.hpp"
#include "crypto.hpp"
#include "connection_pool.hpp"
#include <memory>
#include <unordered_map>
#include <netinet/in.h>

class ClientTcpTunnel : public Tunnel
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
    std::unordered_map<int, uint32_t> client_sessions;

    void setup_listener();
    void handle_new_connection();
    void handle_data(int fd);
    void forward_to_server(int client_fd, uint8_t *data, size_t len);

public:
    ClientTcpTunnel(const std::string &local_addr, int local_port,
                    const std::string &remote_addr, int remote_port,
                    const std::string &key);
    ~ClientTcpTunnel();
    void run() override;
};

#endif