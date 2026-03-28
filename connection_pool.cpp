#include "connection_pool.hpp"

ConnectionPool::ConnectionPool(const std::string &addr, int port, Protocol proto, int pool_size, int rotate_interval_ms)
    : remote_addr(addr), remote_port(port), protocol(proto), pool_size(pool_size), rotate_interval_ms(rotate_interval_ms)
{
    for (int i = 0; i < pool_size; ++i)
    {
        add_connection();
    }
}

void ConnectionPool::add_connection()
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    connections.push_back(std::make_unique<Connection>(remote_addr, remote_port, protocol, rotate_interval_ms));
}

Connection *ConnectionPool::get_current()
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (connections.empty())
        return nullptr;

    auto &conn = connections[current_index % connections.size()];
    if (conn->should_rotate())
    {
        rotate();
    }
    return conn.get();
}

void ConnectionPool::rotate()
{
    current_index++;
    size_t idx = current_index % connections.size();
    connections[idx] = std::make_unique<Connection>(remote_addr, remote_port, protocol, rotate_interval_ms);
}

std::vector<int> ConnectionPool::get_all_fds()
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    std::vector<int> fds;
    for (const auto &conn : connections)
    {
        fds.push_back(conn->get_fd());
    }
    return fds;
}