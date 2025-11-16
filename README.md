# Tiny Tunnel

Bidirectional lightweight tunnel for TCP and UDP forwarding with connection pooling and encryption to bypass restrictions.

## Features

- **Connection Pooling**: Maintains multiple connections to avoid blocks
- **Automatic Rotation**: Rotates connections based on message count or time interval
- **Encryption**: Encryption for all traffic
- **TCP & UDP Support**: Full forwarding capability for both protocols
- **IPv4 & IPv6 Support**: Works with both IPv4 and IPv6 addresses
- **Automatic Failover**: Uses next connection in pool if current fails

## How It Works

```
             persistent * -> 8000                 pooled      * -> 8001                 persistent * -> 8002
[Source App] --------data-------> [Client Tunnel] ---encrypted data---> [Server Tunnel] --------data-------> [Target Server]

             persistent * -> 8000                 pooled      8003 <- *                 persistent * -> 8002
[Source App] <-------data-------- [Client Tunnel] <---encrypted data--- [Server Tunnel] <-------data-------- [Target Server]
```

Idea is that connections between App/Server and Tunnel are persistent, so apps seeing it as usual connections, but connections between Tunnels are constantly being recreated. Connection pool is independent in both directions, so both hosts with Tunnels must have public IP address

## Setup

### Dependencies

Requires OpenSSL and a C++17 compatible compiler (Linux with epoll support).

#### Debian

```bash
sudo apt install libssl-dev
```

### Building

```bash
make
make install  # Install to /usr/local/bin
```

## Usage

Client:

```bash
#             <crypto> <encryption key> <protocol> <type> <local listener> <remote server>   <local response listener>
./tiny-tunnel -c xor   -k mysecretkey   -p udp     client -l 0.0.0.0:8000  -r 127.0.0.1 8001 -R 0.0.0.0 8803
```

Server:

```bash
#             <crypto> <encryption key> <protocol> <type> <local listener> <remote target>   <remote response>
./tiny-tunnel -c xor   -k mysecretkey   -p udp     server -l 0.0.0.0:8001  -r 127.0.0.1 8002 -R 127.0.0.1 8803
```

All traffic can be encrypted using selected algorithm:

1. `aes` - AES-256-CBC with PBKDF
2. `xor` - XOR

You can also mix IPv4 and IPv6 addresses as needed for different endpoints.

## Configuration

The tunnel automatically manages connection pooling with the following defaults:

- **Pool Size**: 3 connections
- **Rotation**: Every 5 seconds or 5 messages
- **Buffer Size**: 64KB

## Protocol

Each packet contains an 8-byte header with:

- `session_id` (4 bytes): Unique session identifier
- `data_len` (2 bytes): Payload length
- `flags` (1 byte): Protocol flags (0x01 for UDP)
- `direction` (1 byte): Direction

## Performance

- Non-blocking I/O with epoll
- TCP connections use keep-alive and TCP_NODELAY
- Minimal packet overhead (8-byte header)
