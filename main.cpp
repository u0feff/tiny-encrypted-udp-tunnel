#include <iostream>
#include <memory>
#include <string>
#include "crypto/aes_crypto.hpp"
#include "crypto/xor_crypto.hpp"
#include "tunnels/tunnel.hpp"
#include "tunnels/client_tcp_tunnel.hpp"
#include "tunnels/server_tcp_tunnel.hpp"
#include "tunnels/client_udp_tunnel.hpp"
#include "tunnels/server_udp_tunnel.hpp"

int main(int argc, char *argv[])
{
    if (argc < 8)
    {
        std::cerr << "Usage: " << argv[0]
                  << " <client|server> <local_addr> <local_port> <remote_addr> <remote_port> "
                  << "<response_addr> <response_port> <key> [--udp]" << std::endl;
        std::cerr << "\nFor client:" << std::endl;
        std::cerr << "  local_addr:local_port - listen for client connections" << std::endl;
        std::cerr << "  remote_addr:remote_port - send requests to server" << std::endl;
        std::cerr << "  response_addr:response_port - listen for responses from server" << std::endl;
        std::cerr << "\nFor server:" << std::endl;
        std::cerr << "  local_addr:local_port - listen for requests" << std::endl;
        std::cerr << "  remote_addr:remote_port - send requests to destination" << std::endl;
        std::cerr << "  response_addr:response_port - send responses to client" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string local_addr = argv[2];
    int local_port = std::stoi(argv[3]);
    std::string remote_addr = argv[4];
    int remote_port = std::stoi(argv[5]);
    std::string response_addr = argv[6];
    int response_port = std::stoi(argv[7]);
    std::string key = argv[8];
    bool use_udp = (argc > 9 && std::string(argv[9]) == "--udp");

    try
    {
        // auto crypto = std::make_shared<AesCrypto>(key);
        auto crypto = std::make_shared<XorCrypto>(key);

        std::unique_ptr<Tunnel> tunnel;

        if (mode == "client")
        {
            if (use_udp)
            {
                tunnel = std::make_unique<ClientUdpTunnel>(
                    local_addr, local_port,
                    remote_addr, remote_port,
                    response_addr, response_port,
                    crypto);
            }
            else
            {
                tunnel = std::make_unique<ClientTcpTunnel>(
                    local_addr, local_port,
                    remote_addr, remote_port,
                    response_addr, response_port,
                    crypto);
            }
        }
        else if (mode == "server")
        {
            if (use_udp)
            {
                tunnel = std::make_unique<ServerUdpTunnel>(
                    local_addr, local_port,
                    remote_addr, remote_port,
                    response_addr, response_port,
                    crypto);
            }
            else
            {
                tunnel = std::make_unique<ServerTcpTunnel>(
                    local_addr, local_port,
                    remote_addr, remote_port,
                    response_addr, response_port,
                    crypto);
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