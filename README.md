# Tiny Tunnel

Bidirectional lightweight tunnel for TCP and UDP forwarding with connection pooling and encryption to bypass restrictions.

## Features

- **Connection Pooling**: Maintains multiple connections to avoid blocks
- **Automatic Rotation**: Rotates connections based on message count or time interval
- **Encryption**: Encryption for all traffic
- **TCP & UDP Support**: Full forwarding capability for both protocols
- **Automatic Failover**: Uses next connection in pool if current fails

## How It Works

```
             persistent * -> 8000                 pooled      * -> 8001                 persistent * -> 8002
[Client App] --------data-------> [Client Tunnel] ---encrypted data---> [Server Tunnel] --------data-------> [Target Server]

             persistent * -> 8000                 pooled      8003 <- *                 persistent * -> 8002
[Client App] <-------data-------- [Client Tunnel] ---encrypted data---> [Server Tunnel] <-------data-------- [Target Server]
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
#             <type> <local listener> <remote tunnel> <local response listener> <encryption key>
./tiny-tunnel client 0.0.0.0 8000     127.0.0.1 8001  0.0.0.0 8803              mysecretkey
```

Server:
```bash
#             <type> <local listener> <remote tunnel> <remote response listener> <encryption key>
./tiny-tunnel server 0.0.0.0 8001     127.0.0.1 8002  0.0.0.0 8803              mysecretkey
```

For UDP add flag `--udp` at end

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
- `reserved` (1 byte): Reserved for future use

All traffic is encrypted using selected algorithm:
1. AES-256-CBC with PBKDF
2. _its all for now_

## Performance

- Non-blocking I/O with epoll
- TCP connections use keep-alive and TCP_NODELAY
- Minimal packet overhead (8-byte header)
