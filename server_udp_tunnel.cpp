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
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &response_addr, int response_port,
                                 const std::string &key)
    : local_addr(local_addr), local_port(local_port),
      remote_addr(remote_addr), remote_port(remote_port), key(key)
{
    crypto = std::make_unique<Crypto>(key);
    session_store = std::make_unique<SessionStore>(remote_addr, remote_port, Protocol::UDP);
    response_pool = std::make_unique<ConnectionPool>(response_addr, response_port, Protocol::UDP);
    epoll_fd = epoll_create1(0);
    setup_listener();

    // Start response monitoring thread
    response_thread = std::thread(&ServerUdpTunnel::monitor_target_responses, this);
}

ServerUdpTunnel::~ServerUdpTunnel()
{
    running = false;
    if (response_thread.joinable())
    {
        response_thread.join();
    }
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
                handle_request_data();
            }
        }
    }
}

void ServerUdpTunnel::handle_request_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len > 0)
    {
        forward_to_target(buffer, len);
    }
}

void ServerUdpTunnel::forward_to_target(uint8_t *data, size_t len)
{
    auto decrypted = crypto->decrypt(data, len);
    if (decrypted.size() < sizeof(TunnelHeader))
        return;

    TunnelHeader *header = (TunnelHeader *)decrypted.data();
    uint32_t session_id = ntohl(header->session_id);
    uint16_t data_len = ntohs(header->data_len);

    if (header->direction != static_cast<uint8_t>(Direction::REQUEST))
        return;
    if (sizeof(TunnelHeader) + data_len > decrypted.size())
        return;

    Connection *target_conn = session_store->get_or_create_session(session_id);
    if (target_conn)
    {
        target_conn->send_data(decrypted.data() + sizeof(TunnelHeader), data_len);
        session_targets[session_id] = target_conn;
    }
}

void ServerUdpTunnel::monitor_target_responses()
{
    uint8_t buffer[BUFFER_SIZE];

    while (running)
    {
        for (auto &[session_id, target_conn] : session_targets)
        {
            if (!target_conn)
                continue;

            ssize_t len = target_conn->recv_data(buffer, BUFFER_SIZE);
            if (len > 0)
            {
                forward_response_to_client(session_id, buffer, len);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void ServerUdpTunnel::forward_response_to_client(uint32_t session_id, uint8_t *data, size_t len)
{
    TunnelHeader header;
    header.session_id = htonl(session_id);
    header.data_len = htons(len);
    header.flags = 0x01;
    header.direction = static_cast<uint8_t>(Direction::RESPONSE);

    std::vector<uint8_t> packet;
    packet.resize(sizeof(header) + len);
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), data, len);

    auto encrypted = crypto->encrypt(packet.data(), packet.size());

    Connection *conn = response_pool->get_current();
    if (conn)
    {
        conn->send_data(encrypted.data(), encrypted.size());
    }
}