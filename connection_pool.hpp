#ifndef CONNECTION_POOL_HPP
#define CONNECTION_POOL_HPP

#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <string>
#include "connection.hpp"
#include "config.hpp"
#include "protocol.hpp"

class ConnectionPool
{
private:
    std::vector<std::unique_ptr<Connection>> connections;
    std::atomic<size_t> current_index{0};
    std::mutex pool_mutex;
    std::string remote_addr;
    int remote_port;
    Protocol protocol;

public:
    ConnectionPool(const std::string &addr, int port, Protocol proto);
    void add_connection();
    Connection *get_current();
    void rotate();
    std::vector<int> get_all_fds();
};

#endif