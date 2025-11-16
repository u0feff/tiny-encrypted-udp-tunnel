#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include <string>
#include <atomic>
#include <chrono>
#include <netinet/in.h>
#include "config.hpp"
#include "protocol.hpp"

class Connection
{
private:
    int sockfd;
    sockaddr_storage remote_addr;
    socklen_t remote_addr_len;
    std::atomic<int> message_count{0};
    std::chrono::steady_clock::time_point creation_time;
    Protocol protocol;

public:
    Connection(const std::string &addr, int port, Protocol proto);
    ~Connection();
    bool should_rotate() const;
    ssize_t send_data(const uint8_t *data, size_t len);
    ssize_t recv_data(uint8_t *buffer, size_t max_len);
    int get_fd() const;
};

#endif