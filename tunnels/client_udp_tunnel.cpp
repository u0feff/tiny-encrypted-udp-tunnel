#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>
#include "client_udp_tunnel.hpp"
#include "tunnel_header.hpp"
#include "tunnel_direction.hpp"
#include "network_utils.hpp"

ClientUdpTunnel::ClientUdpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &response_addr, int response_port,
                                 std::shared_ptr<Crypto> crypto)
    : local_addr(local_addr), local_port(local_port),
      response_addr(response_addr), response_port(response_port),
      crypto(crypto)
{
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
    int addr_family = get_address_family(local_addr);
    listen_fd = socket(addr_family, SOCK_DGRAM, 0);

    sockaddr_storage addr;
    socklen_t addr_len;
    setup_sockaddr(addr, addr_len, local_addr, local_port);

    if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0)
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
    int addr_family = get_address_family(response_addr);
    response_listen_fd = socket(addr_family, SOCK_DGRAM, 0);

    sockaddr_storage addr;
    socklen_t addr_len;
    setup_sockaddr(addr, addr_len, response_addr, response_port);

    if (bind(response_listen_fd, (struct sockaddr *)&addr, addr_len) < 0)
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
                handle_request_data();
            }
            else if (events[i].data.fd == response_listen_fd)
            {
                handle_response_data();
            }
        }
    }
}

void ClientUdpTunnel::handle_request_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len <= 0)
        return;

    forward_request_to_server(buffer, len, sender_addr, addr_len);
}

void ClientUdpTunnel::forward_request_to_server(uint8_t *data, size_t len, const sockaddr_storage &source_addr, socklen_t source_addr_len)
{
    std::string source_addr_str = addr_to_string(source_addr);

    uint32_t session_id;
    auto it = source_addr_to_session_id.find(source_addr_str);
    if (it == source_addr_to_session_id.end())
    {
        session_id = next_session_id++;
        source_addr_to_session_id[source_addr_str] = session_id;
        session_id_to_source_addr[session_id] = std::make_pair(source_addr, source_addr_len);
    }
    else
    {
        session_id = it->second;
    }

    TunnelHeader header;
    header.session_id = htonl(session_id);
    header.data_len = htons(len);
    header.flags = 0x01;
    header.direction = static_cast<uint8_t>(TunnelDirection::REQUEST);

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

void ClientUdpTunnel::handle_response_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(response_listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len <= 0)
        return;

    forward_response_to_source(buffer, len);
}

void ClientUdpTunnel::forward_response_to_source(uint8_t *data, size_t len)
{
    auto decrypted = crypto->decrypt(data, len);
    if (decrypted.size() < sizeof(TunnelHeader))
        return;

    TunnelHeader *header = (TunnelHeader *)decrypted.data();
    uint32_t session_id = ntohl(header->session_id);
    uint16_t data_len = ntohs(header->data_len);

    if (header->direction != static_cast<uint8_t>(TunnelDirection::RESPONSE))
        return;
    if (sizeof(TunnelHeader) + data_len > decrypted.size())
        return;

    auto it = session_id_to_source_addr.find(session_id);
    if (it != session_id_to_source_addr.end())
    {
        sendto(listen_fd, decrypted.data() + sizeof(TunnelHeader), data_len, 0,
               (struct sockaddr *)&it->second.first, it->second.second);
    }
}

std::string ClientUdpTunnel::addr_to_string(const sockaddr_storage &addr)
{
    char str[INET6_ADDRSTRLEN];
    int port;

    if (addr.ss_family == AF_INET6)
    {
        const sockaddr_in6 *addr6 = (const sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN);
        port = ntohs(addr6->sin6_port);
    }
    else
    {
        const sockaddr_in *addr4 = (const sockaddr_in *)&addr;
        inet_ntop(AF_INET, &addr4->sin_addr, str, INET_ADDRSTRLEN);
        port = ntohs(addr4->sin_port);
    }

    return std::string(str) + ":" + std::to_string(port);
}