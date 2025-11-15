#include "connection.hpp"
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

Connection::Connection(const std::string &addr, int port, Protocol proto)
    : protocol(proto), creation_time(std::chrono::steady_clock::now())
{

    if (protocol == Protocol::UDP)
    {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    }
    else
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        int flag = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    inet_pton(AF_INET, addr.c_str(), &remote_addr.sin_addr);

    if (protocol == Protocol::TCP)
    {
        if (connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
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
           duration.count() > ROTATE_INTERVAL_MS;
}

ssize_t Connection::send_data(const uint8_t *data, size_t len)
{
    message_count++;
    if (protocol == Protocol::UDP)
    {
        return sendto(sockfd, data, len, 0,
                      (struct sockaddr *)&remote_addr, sizeof(remote_addr));
    }
    return send(sockfd, data, len, MSG_NOSIGNAL);
}

ssize_t Connection::recv_data(uint8_t *buffer, size_t max_len)
{
    if (protocol == Protocol::UDP)
    {
        socklen_t addr_len = sizeof(remote_addr);
        return recvfrom(sockfd, buffer, max_len, 0,
                        (struct sockaddr *)&remote_addr, &addr_len);
    }
    return recv(sockfd, buffer, max_len, 0);
}

int Connection::get_fd() const
{
    return sockfd;
}