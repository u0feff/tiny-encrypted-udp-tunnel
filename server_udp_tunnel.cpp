#include "server_udp_tunnel.hpp"
#include "config.hpp"
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>

ServerUdpTunnel::ServerUdpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &target_addr, int target_port,
                                 const std::string &key)
    : local_addr(local_addr), local_port(local_port),
      target_addr(target_addr), target_port(target_port), key(key)
{
    crypto = std::make_unique<Crypto>(key);
    session_store = std::make_unique<SessionStore>(target_addr, target_port, Protocol::UDP);
    epoll_fd = epoll_create1(0);
    setup_listener();
}

ServerUdpTunnel::~ServerUdpTunnel()
{
    running = false;
    if (listen_fd >= 0)
        close(listen_fd);
    if (epoll_fd >= 0)
        close(epoll_fd);
}

void ServerUdpTunnel::setup_listener()
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

void ServerUdpTunnel::run()
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

void ServerUdpTunnel::handle_udp_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len > 0)
    {
        forward_to_target(buffer, len, sender_addr);
    }
}

void ServerUdpTunnel::forward_to_target(uint8_t *data, size_t len, const sockaddr_in &sender)
{
    auto decrypted = crypto->decrypt(data, len);
    if (decrypted.size() < sizeof(TunnelHeader))
        return;

    TunnelHeader *header = (TunnelHeader *)decrypted.data();
    uint32_t session_id = ntohl(header->session_id);
    uint16_t data_len = ntohs(header->data_len);

    if (sizeof(TunnelHeader) + data_len > decrypted.size())
        return;

    Connection *target_conn = session_store->get_or_create_session(session_id);
    if (target_conn)
    {
        target_conn->send_data(decrypted.data() + sizeof(TunnelHeader), data_len);
    }

    udp_sessions[session_id] = sender;
}