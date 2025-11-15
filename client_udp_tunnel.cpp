#include "client_udp_tunnel.hpp"
#include "config.hpp"
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>

ClientUdpTunnel::ClientUdpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &key)
    : local_addr(local_addr), local_port(local_port),
      remote_addr(remote_addr), remote_port(remote_port), key(key)
{
    crypto = std::make_unique<Crypto>(key);
    pool = std::make_unique<ConnectionPool>(remote_addr, remote_port, Protocol::UDP);
    epoll_fd = epoll_create1(0);
    setup_listener();
}

ClientUdpTunnel::~ClientUdpTunnel()
{
    running = false;
    if (listen_fd >= 0)
        close(listen_fd);
    if (epoll_fd >= 0)
        close(epoll_fd);
}

void ClientUdpTunnel::setup_listener()
{
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    inet_pton(AF_INET, local_addr.c_str(), &addr.sin_addr);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        throw std::runtime_error("Bind failed");
    }

    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
}

void ClientUdpTunnel::run()
{
    epoll_event events[MAX_EVENTS];

    while (running)
    {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd == listen_fd)
            {
                handle_udp_data();
            }
        }
    }
}

void ClientUdpTunnel::handle_udp_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len > 0)
    {
        forward_to_server(buffer, len, sender_addr);
    }
}

void ClientUdpTunnel::forward_to_server(uint8_t *data, size_t len, const sockaddr_in &sender)
{
    uint32_t session_id = next_session_id++;

    TunnelHeader header;
    header.session_id = htonl(session_id);
    header.data_len = htons(len);
    header.flags = 0x01;
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

    udp_sessions[session_id] = sender;
}