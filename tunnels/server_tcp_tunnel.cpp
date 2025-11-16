#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>
#include "server_tcp_tunnel.hpp"
#include "tunnel_header.hpp"
#include "tunnel_direction.hpp"
#include "network_utils.hpp"

ServerTcpTunnel::ServerTcpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &response_addr, int response_port,
                                 std::shared_ptr<Crypto> crypto)
    : local_addr(local_addr), local_port(local_port),
      crypto(crypto)
{
    session_store = std::make_unique<SessionStore>(remote_addr, remote_port, Protocol::TCP);
    response_pool = std::make_unique<ConnectionPool>(response_addr, response_port, Protocol::TCP);
    epoll_fd = epoll_create1(0);
    setup_listener();
}

ServerTcpTunnel::~ServerTcpTunnel()
{
    running = false;
    if (listen_fd >= 0)
        close(listen_fd);
    if (epoll_fd >= 0)
        close(epoll_fd);
}

void ServerTcpTunnel::setup_listener()
{
    int addr_family = get_address_family(local_addr);
    listen_fd = socket(addr_family, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_storage addr;
    socklen_t addr_len;
    setup_sockaddr(addr, addr_len, local_addr, local_port);

    if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0)
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

void ServerTcpTunnel::run()
{
    epoll_event events[MAX_EVENTS];

    while (running)
    {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd == listen_fd)
            {
                handle_client_connection();
            }
            else
            {
                auto it = target_fd_to_session_id.find(events[i].data.fd);
                if (it != target_fd_to_session_id.end())
                {
                    handle_response_data(events[i].data.fd);
                }
                else
                {
                    handle_request_data(events[i].data.fd);
                }
            }
        }
    }
}

void ServerTcpTunnel::handle_client_connection()
{
    sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);

    if (client_fd < 0)
        return;

    fcntl(client_fd, F_SETFL, O_NONBLOCK);
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
}

void ServerTcpTunnel::handle_request_data(int fd)
{
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len = recv(fd, buffer, BUFFER_SIZE, 0);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        return;
    }

    forward_request_to_target(buffer, len);
}

void ServerTcpTunnel::forward_request_to_target(uint8_t *data, size_t len)
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

void ServerTcpTunnel::add_target_to_epoll(Connection *target_conn, uint32_t session_id)
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

void ServerTcpTunnel::handle_response_data(int target_fd)
{
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len = recv(target_fd, buffer, BUFFER_SIZE, 0);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_fd, nullptr);
        close(target_fd);
        auto it = target_fd_to_session_id.find(target_fd);
        if (it != target_fd_to_session_id.end())
        {
            session_store->remove_session(it->second);
            target_fd_to_session_id.erase(target_fd);
        }
        return;
    }

    auto it = target_fd_to_session_id.find(target_fd);
    if (it != target_fd_to_session_id.end())
    {
        forward_response_to_client(it->second, buffer, len);
    }
}

void ServerTcpTunnel::forward_response_to_client(uint32_t session_id, uint8_t *data, size_t len)
{
    TunnelHeader header;
    header.session_id = htonl(session_id);
    header.data_len = htons(len);
    header.flags = 0;
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