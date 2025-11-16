#include <iostream>
#include <memory>
#include <string>
#include <CLI/CLI.hpp>
#include "crypto/aes_crypto.hpp"
#include "crypto/xor_crypto.hpp"
#include "tunnels/tunnel.hpp"
#include "tunnels/client_tcp_tunnel.hpp"
#include "tunnels/server_tcp_tunnel.hpp"
#include "tunnels/client_udp_tunnel.hpp"
#include "tunnels/server_udp_tunnel.hpp"

struct Config
{
    std::string local_host = "::";
    uint16_t local_port;
    std::string remote_host;
    uint16_t remote_port;
    std::string response_host;
    uint16_t response_port;
    std::string key;
    std::string crypto;
    std::string protocol;
};

int main(int argc, char *argv[])
{
    CLI::App app{"Tiny Tunnel - Rotating encrypted TCP/UDP tunnel"};

    app.set_version_flag("-v,--version", "1.0.0");

    Config config;

    auto client = app.add_subcommand("client", "Run as client (accepts local connections and forwards to server)");
    auto server = app.add_subcommand("server", "Run as server (receives from client and forwards to remote)");

    // Client-specific options
    client->add_option_function<std::string>(
              "-l,--local",
              [&config](const std::string &val)
              {
                  auto pos = val.find_last_of(':');
                  if (pos != std::string::npos)
                  {
                      config.local_host = val.substr(0, pos);
                      config.local_port = std::stoi(val.substr(pos + 1));
                  }
                  else
                  {
                      config.local_port = std::stoi(val);
                  }
              },
              "Local listen address (host:port or port)")
        ->required();

    client->add_option_function<std::string>(
              "-r,--remote",
              [&config](const std::string &val)
              {
                  auto pos = val.find_last_of(':');
                  if (pos != std::string::npos)
                  {
                      config.remote_host = val.substr(0, pos);
                      config.remote_port = std::stoi(val.substr(pos + 1));
                  }
                  else
                  {
                      throw CLI::ValidationError("Remote must be specified as host:port");
                  }
              },
              "Remote address (host:port)")
        ->required();

    client->add_option_function<std::string>(
              "-R,--response",
              [&config](const std::string &val)
              {
                  auto pos = val.find_last_of(':');
                  if (pos != std::string::npos)
                  {
                      config.response_host = val.substr(0, pos);
                      config.response_port = std::stoi(val.substr(pos + 1));
                  }
                  else
                  {
                      config.response_host = "::";
                      config.response_port = std::stoi(val);
                  }
              },
              "Response listen address (host:port or port)")
        ->required();

    // Server-specific options
    server->add_option_function<std::string>(
              "-l,--local",
              [&config](const std::string &val)
              {
                  auto pos = val.find_last_of(':');
                  if (pos != std::string::npos)
                  {
                      config.local_host = val.substr(0, pos);
                      config.local_port = std::stoi(val.substr(pos + 1));
                  }
                  else
                  {
                      config.local_port = std::stoi(val);
                  }
              },
              "Local listen address (host:port or port)")
        ->required();

    server->add_option_function<std::string>(
              "-r,--remote",
              [&config](const std::string &val)
              {
                  auto pos = val.find_last_of(':');
                  if (pos != std::string::npos)
                  {
                      config.remote_host = val.substr(0, pos);
                      config.remote_port = std::stoi(val.substr(pos + 1));
                  }
                  else
                  {
                      config.remote_host = "::1";
                      config.remote_port = std::stoi(val);
                  }
              },
              "Remote address (host:port or port)")
        ->required();

    server->add_option_function<std::string>(
              "-R,--response",
              [&config](const std::string &val)
              {
                  auto pos = val.find_last_of(':');
                  if (pos != std::string::npos)
                  {
                      config.response_host = val.substr(0, pos);
                      config.response_port = std::stoi(val.substr(pos + 1));
                  }
                  else
                  {
                      throw CLI::ValidationError("Remote must be specified as host:port");
                  }
              },
              "Response address (host:port)")
        ->required();

    // Common options
    app.add_option("-c,--crypto", config.crypto, "Crypto")
        ->required()
        ->check(CLI::IsMember({"xor", "aes"}));

    app.add_option("-k,--key", config.key, "Crypto key")
        ->required();

    app.add_option("-p,--protocol", config.protocol, "Network protocol")
        ->required()
        ->check(CLI::IsMember({"udp", "tcp"}));

    app.require_subcommand(1);

    CLI11_PARSE(app, argc, argv);

    try
    {
        std::shared_ptr<Crypto> crypto;
        if (config.crypto == "aes")
        {
            crypto = std::make_shared<AesCrypto>(config.key);
        }
        else if (config.crypto == "xor")
        {
            crypto = std::make_shared<XorCrypto>(config.key);
        }
        else
        {
            throw std::runtime_error("Unknown crypto: " + config.crypto);
        }

        std::unique_ptr<Tunnel> tunnel;

        if (client->parsed())
        {
            if (config.protocol == "udp")
            {
                tunnel = std::make_unique<ClientUdpTunnel>(
                    config.local_host, config.local_port,
                    config.remote_host, config.remote_port,
                    config.response_host, config.response_port,
                    crypto);
            }
            else if (config.protocol == "tcp")
            {
                tunnel = std::make_unique<ClientTcpTunnel>(
                    config.local_host, config.local_port,
                    config.remote_host, config.remote_port,
                    config.response_host, config.response_port,
                    crypto);
            }
            else
            {
                throw std::runtime_error("Unknown protocol: " + config.protocol);
            }
        }
        else if (server->parsed())
        {
            if (config.protocol == "udp")
            {
                tunnel = std::make_unique<ServerUdpTunnel>(
                    config.local_host, config.local_port,
                    config.remote_host, config.remote_port,
                    config.response_host, config.response_port,
                    crypto);
            }
            else if (config.protocol == "tcp")
            {
                tunnel = std::make_unique<ServerTcpTunnel>(
                    config.local_host, config.local_port,
                    config.remote_host, config.remote_port,
                    config.response_host, config.response_port,
                    crypto);
            }
            else
            {
                throw std::runtime_error("Unknown protocol: " + config.protocol);
            }
        }
        else
        {
            throw std::runtime_error("Unknown mode");
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