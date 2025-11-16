#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdexcept>
#include "client_tcp_tunnel.hpp"
#include "tunnel_header.hpp"
#include "tunnel_direction.hpp"
#include "network_utils.hpp"

constexpr uintptr_t CONN_TYPE_REQUEST = 3;
constexpr uintptr_t CONN_TYPE_RESPONSE = 4;

ClientTcpTunnel::ClientTcpTunnel(const std::string &local_addr, int local_port,
                                 const std::string &remote_addr, int remote_port,
                                 const std::string &response_addr, int response_port,
                                 std::shared_ptr<Crypto> crypto)
    : local_addr(local_addr), local_port(local_port),
      response_addr(response_addr), response_port(response_port),
      crypto(crypto)
{
    request_pool = std::make_unique<ConnectionPool>(remote_addr, remote_port, Protocol::TCP);
    epoll_fd = epoll_create1(0);
    setup_listener();
    setup_response_listener();
}

ClientTcpTunnel::~ClientTcpTunnel()
{
    running = false;
    if (listen_fd >= 0)
        close(listen_fd);
    if (response_listen_fd >= 0)
        close(response_listen_fd);
    if (epoll_fd >= 0)
        close(epoll_fd);
}

void ClientTcpTunnel::setup_listener()
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
        throw std::runtime_error("Bind failed on request port");
    }

    listen(listen_fd, 128);
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    ev.data.ptr = (void *)1; // Mark as request listener
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
}

void ClientTcpTunnel::setup_response_listener()
{
    int addr_family = get_address_family(response_addr);
    response_listen_fd = socket(addr_family, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(response_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_storage addr;
    socklen_t addr_len;
    setup_sockaddr(addr, addr_len, response_addr, response_port);

    if (bind(response_listen_fd, (struct sockaddr *)&addr, addr_len) < 0)
    {
        throw std::runtime_error("Bind failed on response port");
    }

    listen(response_listen_fd, 128);
    fcntl(response_listen_fd, F_SETFL, O_NONBLOCK);

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = response_listen_fd;
    ev.data.ptr = (void *)2; // Mark as response listener
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, response_listen_fd, &ev);
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
                handle_source_connection();
            }
            else if (events[i].data.fd == response_listen_fd)
            {
                handle_response_connection();
            }
            else
            {
                uintptr_t type = (uintptr_t)events[i].data.ptr;
                if (type == CONN_TYPE_REQUEST)
                {
                    handle_request_data(events[i].data.fd);
                }
                else if (type == CONN_TYPE_RESPONSE)
                {
                    handle_response_data(events[i].data.fd);
                }
            }
        }
    }
}

void ClientTcpTunnel::handle_source_connection()
{
    sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int source_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);

    if (source_fd < 0)
        return;

    fcntl(source_fd, F_SETFL, O_NONBLOCK);
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = source_fd;
    ev.data.ptr = reinterpret_cast<void *>(CONN_TYPE_REQUEST);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, source_fd, &ev);

    uint32_t session_id = next_session_id++;
    source_fd_to_session_id[source_fd] = session_id;
    session_id_to_source_fd[session_id] = source_fd;
}

void ClientTcpTunnel::handle_response_connection()
{
    sockaddr_storage server_addr;
    socklen_t addr_len = sizeof(server_addr);
    int response_fd = accept(response_listen_fd, (struct sockaddr *)&server_addr, &addr_len);

    if (response_fd < 0)
        return;

    fcntl(response_fd, F_SETFL, O_NONBLOCK);
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = response_fd;
    ev.data.ptr = reinterpret_cast<void *>(CONN_TYPE_RESPONSE);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, response_fd, &ev);
}

void ClientTcpTunnel::handle_request_data(int fd)
{
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len = recv(fd, buffer, BUFFER_SIZE, 0);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        auto it = source_fd_to_session_id.find(fd);
        if (it != source_fd_to_session_id.end())
        {
            session_id_to_source_fd.erase(it->second);
            source_fd_to_session_id.erase(fd);
        }
        return;
    }

    forward_request_to_server(buffer, len, fd);
}

void ClientTcpTunnel::forward_request_to_server(uint8_t *data, size_t len, int source_fd)
{
    auto it = source_fd_to_session_id.find(source_fd);
    if (it == source_fd_to_session_id.end())
        return;

    TunnelHeader header;
    header.session_id = htonl(it->second);
    header.data_len = htons(len);
    header.flags = 0;
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

void ClientTcpTunnel::handle_response_data(int fd)
{
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len = recv(fd, buffer, BUFFER_SIZE, 0);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        return;
    }

    forward_response_to_source(buffer, len);
}

void ClientTcpTunnel::forward_response_to_source(uint8_t *data, size_t len)
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

    auto it = session_id_to_source_fd.find(session_id);
    if (it != session_id_to_source_fd.end())
    {
        send(it->second, decrypted.data() + sizeof(TunnelHeader), data_len, MSG_NOSIGNAL);
    }
}