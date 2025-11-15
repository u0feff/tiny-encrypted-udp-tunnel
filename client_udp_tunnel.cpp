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
                                 const std::string &response_addr, int response_port,
                                 const std::string &key)
    : local_addr(local_addr), local_port(local_port),
      response_addr(response_addr), response_port(response_port), key(key)
{
    crypto = std::make_unique<Crypto>(key);
    request_pool = std::make_unique<ConnectionPool>(remote_addr, remote_port, Protocol::UDP);
    epoll_fd = epoll_create1(0);
    setup_listener();
    setup_response_listener();
}

ClientUdpTunnel::~ClientUdpTunnel()
{
    running = false;
    if (listen_fd >= 0)
        close(listen_fd);
    if (response_listen_fd >= 0)
        close(response_listen_fd);
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
        throw std::runtime_error("Bind failed on request port");
    }

    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
}

void ClientUdpTunnel::setup_response_listener()
{
    response_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(response_port);
    inet_pton(AF_INET, response_addr.c_str(), &addr.sin_addr);

    if (bind(response_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        throw std::runtime_error("Bind failed on response port");
    }

    fcntl(response_listen_fd, F_SETFL, O_NONBLOCK);

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = response_listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, response_listen_fd, &ev);
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
                handle_client_data();
            }
            else if (events[i].data.fd == response_listen_fd)
            {
                handle_response_data();
            }
        }
    }
}

void ClientUdpTunnel::handle_client_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len > 0)
    {
        forward_request_to_server(buffer, len, sender_addr);
    }
}

void ClientUdpTunnel::handle_response_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(response_listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len > 0)
    {
        forward_response_to_client(buffer, len);
    }
}

void ClientUdpTunnel::forward_request_to_server(uint8_t *data, size_t len, const sockaddr_in &sender)
{
    std::string client_key = addr_to_string(sender);

    uint32_t session_id;
    auto it = client_to_session.find(client_key);
    if (it == client_to_session.end())
    {
        session_id = next_session_id++;
        UdpSession session;
        session.client_addr = sender;
        session.session_id = session_id;
        session.last_activity = std::chrono::steady_clock::now();
        client_to_session[client_key] = session;
        session_to_client[session_id] = sender;
    }
    else
    {
        session_id = it->second.session_id;
        it->second.last_activity = std::chrono::steady_clock::now();
    }

    TunnelHeader header;
    header.session_id = htonl(session_id);
    header.data_len = htons(len);
    header.flags = 0x01;
    header.direction = static_cast<uint8_t>(Direction::REQUEST);

    std::vector<uint8_t> packet;
    packet.resize(sizeof(header) + len);
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), data, len);

    auto encrypted = crypto->encrypt(packet.data(), packet.size());

    Connection *conn = request_pool->get_current();
    if (conn)
    {
        conn->send_data(encrypted.data(), encrypted.size());
    }
}

void ClientUdpTunnel::forward_response_to_client(uint8_t *data, size_t len)
{
    auto decrypted = crypto->decrypt(data, len);
    if (decrypted.size() < sizeof(TunnelHeader))
        return;

    TunnelHeader *header = (TunnelHeader *)decrypted.data();
    uint32_t session_id = ntohl(header->session_id);
    uint16_t data_len = ntohs(header->data_len);

    if (header->direction != static_cast<uint8_t>(Direction::RESPONSE))
        return;
    if (sizeof(TunnelHeader) + data_len > decrypted.size())
        return;

    auto it = session_to_client.find(session_id);
    if (it != session_to_client.end())
    {
        sendto(listen_fd, decrypted.data() + sizeof(TunnelHeader), data_len, 0,
               (struct sockaddr *)&it->second, sizeof(it->second));
    }
}

std::string ClientUdpTunnel::addr_to_string(const sockaddr_in &addr)
{
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, str, INET_ADDRSTRLEN);
    return std::string(str) + ":" + std::to_string(ntohs(addr.sin_port));
}