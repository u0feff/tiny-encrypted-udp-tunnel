#include "connection.hpp"
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include "network_utils.hpp"

Connection::Connection(const std::string &addr, int port, Protocol proto, int rotate_interval_ms)
    : creation_time(std::chrono::steady_clock::now()), protocol(proto), rotate_interval_ms(rotate_interval_ms)
{
    int addr_family = get_address_family(addr);
    
    if (protocol == Protocol::UDP)
    {
        sockfd = socket(addr_family, SOCK_DGRAM, 0);
    }
    else
    {
        sockfd = socket(addr_family, SOCK_STREAM, 0);
        int flag = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
    }

    setup_sockaddr(remote_addr, remote_addr_len, addr, port);

    if (protocol == Protocol::TCP)
    {
        if (connect(sockfd, (struct sockaddr *)&remote_addr, remote_addr_len) < 0)
        {
            close(sockfd);
            throw std::runtime_error("Connection failed");
        }
    }

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
}

Connection::~Connection()
{
    if (sockfd >= 0)
    {
        close(sockfd);
    }
}

bool Connection::should_rotate() const
{
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - creation_time);
    return message_count >= MAX_MESSAGES_PER_CONNECTION ||
           duration.count() > rotate_interval_ms;
}

ssize_t Connection::send_data(const uint8_t *data, size_t len)
{
    message_count++;
    if (protocol == Protocol::UDP)
    {
        return sendto(sockfd, data, len, 0,
                      (struct sockaddr *)&remote_addr, remote_addr_len);
    }
    return send(sockfd, data, len, MSG_NOSIGNAL);
}

ssize_t Connection::recv_data(uint8_t *buffer, size_t max_len)
{
    if (protocol == Protocol::UDP)
    {
        socklen_t addr_len = remote_addr_len;
        return recvfrom(sockfd, buffer, max_len, 0,
                        (struct sockaddr *)&remote_addr, &addr_len);
    }
    return recv(sockfd, buffer, max_len, 0);
}

int Connection::get_fd() const
{
    return sockfd;
}