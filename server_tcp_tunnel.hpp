#ifndef SERVER_TCP_TUNNEL_HPP
#define SERVER_TCP_TUNNEL_HPP

#include "tunnel.hpp"
#include "crypto.hpp"
#include "session_store.hpp"
#include "connection_pool.hpp"
#include <memory>
#include <unordered_map>
#include <netinet/in.h>

class ServerTcpTunnel : public Tunnel
{
private:
    std::string local_addr;
    int local_port;
    std::string remote_addr;
    int remote_port;
    std::string key;

    std::unique_ptr<Crypto> crypto;
    std::unique_ptr<SessionStore> session_store;
    std::unique_ptr<ConnectionPool> response_pool;
    int listen_fd;
    int epoll_fd;
    std::unordered_map<int, uint32_t> target_to_session;

    void setup_listener();
    void handle_new_connection();
    void handle_data(int fd);
    void handle_target_response(int target_fd);
    void forward_to_target(int server_fd, uint8_t *data, size_t len);
    void forward_response_to_client(uint32_t session_id, uint8_t *data, size_t len);

public:
    ServerTcpTunnel(const std::string &local_addr, int local_port,
                    const std::string &remote_addr, int remote_port,
                    const std::string &key);
    ~ServerTcpTunnel();
    void run() override;
};

#endif