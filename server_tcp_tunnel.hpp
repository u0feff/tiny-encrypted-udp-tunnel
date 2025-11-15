#ifndef SERVER_TCP_TUNNEL_HPP
#define SERVER_TCP_TUNNEL_HPP

#include "tunnel.hpp"
#include "crypto.hpp"
#include "session_store.hpp"
#include <memory>
#include <netinet/in.h>

class ServerTcpTunnel : public Tunnel
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

    void setup_listener();
    void handle_new_connection();
    void handle_data(int fd);
    void forward_to_target(int server_fd, uint8_t *data, size_t len);

public:
    ServerTcpTunnel(const std::string &local_addr, int local_port,
                    const std::string &target_addr, int target_port,
                    const std::string &key);
    ~ServerTcpTunnel();
    void run() override;
};

#endif