#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>
#include "server_udp_tunnel.hpp"
#include "tunnel_header.hpp"
#include "tunnel_direction.hpp"
#include "network_utils.hpp"

ServerUdpTunnel::ServerUdpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &response_addr, int response_port,
                                 std::shared_ptr<Crypto> crypto)
    : local_addr(local_addr), local_port(local_port),
      crypto(crypto)
{
    session_store = std::make_unique<SessionStore>(remote_addr, remote_port, Protocol::UDP);
    response_pool = std::make_unique<ConnectionPool>(response_addr, response_port, Protocol::UDP);
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
    int addr_family = get_address_family(local_addr);
    listen_fd = socket(addr_family, SOCK_DGRAM, 0);

    sockaddr_storage addr;
    socklen_t addr_len;
    setup_sockaddr(addr, addr_len, local_addr, local_port);

    if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0)
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
            else
            {
                handle_response_data(events[i].data.fd);
            }
        }
    }
}

void ServerUdpTunnel::handle_request_data()
{
    uint8_t buffer[BUFFER_SIZE];
    sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(listen_fd, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr *)&sender_addr, &addr_len);

    if (len <= 0)
        return;

    forward_request_to_target(buffer, len);
}

void ServerUdpTunnel::forward_request_to_target(uint8_t *data, size_t len)
{
    auto decrypted = crypto->decrypt(data, len);
    if (decrypted.size() < sizeof(TunnelHeader))
        return;

    TunnelHeader *header = (TunnelHeader *)decrypted.data();
    uint32_t session_id = ntohl(header->session_id);
    uint16_t data_len = ntohs(header->data_len);

    if (header->direction != static_cast<uint8_t>(TunnelDirection::REQUEST))
        return;
    if (sizeof(TunnelHeader) + data_len > decrypted.size())
        return;

    Connection *target_conn = session_store->get_or_create_session(session_id);
    if (!target_conn)
        return;

    target_conn->send_data(decrypted.data() + sizeof(TunnelHeader), data_len);

    add_target_to_epoll(target_conn, session_id);
}

void ServerUdpTunnel::add_target_to_epoll(Connection *target_conn, uint32_t session_id)
{
    int target_fd = target_conn->get_fd();

    auto it = target_fd_to_session_id.find(target_fd);
    if (it != target_fd_to_session_id.end())
        return;

    target_fd_to_session_id[target_fd] = session_id;

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = target_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_fd, &ev);
}

void ServerUdpTunnel::handle_response_data(int target_fd)
{
    uint8_t buffer[BUFFER_SIZE];

    auto it = target_fd_to_session_id.find(target_fd);
    if (it == target_fd_to_session_id.end())
        return;

    uint32_t session_id = it->second;
    Connection *target_conn = session_store->get_or_create_session(session_id);
    if (!target_conn)
        return;

    ssize_t len = target_conn->recv_data(buffer, BUFFER_SIZE);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_fd, nullptr);
        target_fd_to_session_id.erase(target_fd);
        session_store->remove_session(session_id);
        return;
    }

    forward_response_to_client(session_id, buffer, len);
}

void ServerUdpTunnel::forward_response_to_client(uint32_t session_id, uint8_t *data, size_t len)
{
    TunnelHeader header;
    header.session_id = htonl(session_id);
    header.data_len = htons(len);
    header.flags = 0x01;
    header.direction = static_cast<uint8_t>(TunnelDirection::RESPONSE);

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