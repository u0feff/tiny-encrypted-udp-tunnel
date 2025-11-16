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
                handle_new_connection();
            }
            else if (events[i].data.fd == response_listen_fd)
            {
                handle_response_connection();
            }
            else
            {
                uintptr_t type = (uintptr_t)events[i].data.ptr;
                if (type == 3)
                { // Client connection
                    handle_client_data(events[i].data.fd);
                }
                else if (type == 4)
                { // Response connection
                    handle_response_data(events[i].data.fd);
                }
            }
        }
    }
}

void ClientTcpTunnel::handle_new_connection()
{
    sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);

    if (client_fd >= 0)
    {
        fcntl(client_fd, F_SETFL, O_NONBLOCK);
        epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = client_fd;
        ev.data.ptr = (void *)3; // Mark as client connection
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

        uint32_t session_id = next_session_id++;
        client_sessions[client_fd] = session_id;
        session_to_client[session_id] = client_fd;
    }
}

void ClientTcpTunnel::handle_response_connection()
{
    sockaddr_storage server_addr;
    socklen_t addr_len = sizeof(server_addr);
    int response_fd = accept(response_listen_fd, (struct sockaddr *)&server_addr, &addr_len);

    if (response_fd >= 0)
    {
        fcntl(response_fd, F_SETFL, O_NONBLOCK);
        epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = response_fd;
        ev.data.ptr = (void *)4; // Mark as response connection
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, response_fd, &ev);
    }
}

void ClientTcpTunnel::handle_client_data(int fd)
{
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len = recv(fd, buffer, BUFFER_SIZE, 0);

    if (len <= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        auto it = client_sessions.find(fd);
        if (it != client_sessions.end())
        {
            session_to_client.erase(it->second);
            client_sessions.erase(fd);
        }
        return;
    }

    forward_request_to_server(fd, buffer, len);
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

    forward_response_to_client(fd, buffer, len);
}

void ClientTcpTunnel::forward_request_to_server(int client_fd, uint8_t *data, size_t len)
{
    auto it = client_sessions.find(client_fd);
    if (it == client_sessions.end())
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

void ClientTcpTunnel::forward_response_to_client(int response_fd, uint8_t *data, size_t len)
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

    auto it = session_to_client.find(session_id);
    if (it != session_to_client.end())
    {
        send(it->second, decrypted.data() + sizeof(TunnelHeader), data_len, MSG_NOSIGNAL);
    }
}