#ifndef SERVER_UDP_TUNNEL_HPP
#define SERVER_UDP_TUNNEL_HPP

#include "tunnel.hpp"
#include "crypto.hpp"
#include "session_store.hpp"
#include "connection_pool.hpp"
#include <memory>
#include <unordered_map>
#include <netinet/in.h>
#include <thread>

class ServerUdpTunnel : public Tunnel
{
private:
    std::string local_addr;
    int local_port;
    std::string key;

    std::unique_ptr<Crypto> crypto;
    std::unique_ptr<SessionStore> session_store;
    std::unique_ptr<ConnectionPool> response_pool;
    int listen_fd;
    int epoll_fd;
    std::unordered_map<uint32_t, Connection *> session_targets;
    std::unordered_map<int, uint32_t> target_fd_to_session;

    void setup_listener();
    void handle_request_data();
    void forward_to_target(uint8_t *data, size_t len);
    void add_target_to_epoll(Connection *target_conn, uint32_t session_id);
    void handle_target_response(int target_fd);
    void forward_response_to_client(uint32_t session_id, uint8_t *data, size_t len);

public:
    ServerUdpTunnel(const std::string &local_addr, int local_port,
                    const std::string &remote_addr, int remote_port,
                    const std::string &response_addr, int response_port,
                    const std::string &key);
    ~ServerUdpTunnel();
    void run() override;
};

#endif