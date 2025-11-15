#include <iostream>
#include <memory>
#include <string>
#include "tunnel.hpp"
#include "client_tcp_tunnel.hpp"
#include "server_tcp_tunnel.hpp"
#include "client_udp_tunnel.hpp"
#include "server_udp_tunnel.hpp"

int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        std::cerr << "Usage: " << argv[0]
                  << " <client|server> <local_addr> <local_port> <remote_addr> <remote_port> "
                  << "<key> [--udp]" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string local_addr = argv[2];
    int local_port = std::stoi(argv[3]);
    std::string remote_addr = argv[4];
    int remote_port = std::stoi(argv[5]);
    std::string key = argv[6];
    bool use_udp = (argc > 7 && std::string(argv[7]) == "--udp");

    try
    {
        std::unique_ptr<Tunnel> tunnel;

        if (mode == "client")
        {
            if (use_udp)
            {
                tunnel = std::make_unique<ClientUdpTunnel>(
                    local_addr, local_port, remote_addr, remote_port, key);
            }
            else
            {
                tunnel = std::make_unique<ClientTcpTunnel>(
                    local_addr, local_port, remote_addr, remote_port, key);
            }
        }
        else if (mode == "server")
        {
            if (use_udp)
            {
                tunnel = std::make_unique<ServerUdpTunnel>(
                    local_addr, local_port, remote_addr, remote_port, key);
            }
            else
            {
                tunnel = std::make_unique<ServerTcpTunnel>(
                    local_addr, local_port, remote_addr, remote_port, key);
            }
        }
        else
        {
            std::cerr << "Invalid mode. Use 'client' or 'server'" << std::endl;
            return 1;
        }

        tunnel->run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}