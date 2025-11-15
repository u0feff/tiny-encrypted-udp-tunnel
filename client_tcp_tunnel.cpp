#include "client_tcp_tunnel.hpp"
#include "config.hpp"
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>

ClientTcpTunnel::ClientTcpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &key)
    : local_addr(local_addr), local_port(local_port),
      remote_addr(remote_addr), remote_port(remote_port), key(key)
{
    crypto = std::make_unique<Crypto>(key);
    pool = std::make_unique<ConnectionPool>(remote_addr, remote_port, Protocol::TCP);
    epoll_fd = epoll_create1(0);
    setup_listener();
}

ClientTcpTunnel::~ClientTcpTunnel()
{
    running = false;
    if (listen_fd >= 0)
        close(listen_fd);
    if (epoll_fd >= 0)
        close(epoll_fd);
}

void ClientTcpTunnel::setup_listener()
{
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    inet_pton(AF_INET, local_addr.c_str(), &addr.sin_addr);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        throw std::runtime_error("Bind failed");
    }

    listen(listen_fd, 128);
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
}

void ClientTcpTunnel::run()
{
    epoll_event events[MAX_EVENTS];

    while (running)
    {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd == listen_fd)
            {
                handle_new_connection();
            }
            else
            {
                handle_data(events[i].data.fd);
            }
        }
    }
}

void ClientTcpTunnel::handle_new_connection()
{
    sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);

    if (client_fd >= 0)
    {
        fcntl(client_fd, F_SETFL, O_NONBLOCK);
        epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = client_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

        uint32_t session_id = next_session_id++;
        client_sessions[client_fd] = session_id;
    }
}

void ClientTcpTunnel::handle_data(int fd)
{
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len = recv(fd, buffer, BUFFER_SIZE, 0);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        client_sessions.erase(fd);
        return;
    }

    forward_to_server(fd, buffer, len);
}

void ClientTcpTunnel::forward_to_server(int client_fd, uint8_t *data, size_t len)
{
    auto it = client_sessions.find(client_fd);
    if (it == client_sessions.end())
        return;

    TunnelHeader header;
    header.session_id = htonl(it->second);
    header.data_len = htons(len);
    header.flags = 0;
    header.reserved = 0;

    std::vector<uint8_t> packet;
    packet.resize(sizeof(header) + len);
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), data, len);

    auto encrypted = crypto->encrypt(packet.data(), packet.size());

    Connection *conn = pool->get_current();
    if (conn)
    {
        conn->send_data(encrypted.data(), encrypted.size());
    }
}