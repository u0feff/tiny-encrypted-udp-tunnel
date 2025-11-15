# Tiny Encrypted UDP Tunnel with Connection Pooling

A lightweight encrypted tunnel that supports both TCP and UDP forwarding with connection pooling to bypass provider restrictions on long-lived connections.

## Features

- **Connection Pooling**: Maintains a pool of connections to avoid provider blocks
- **Automatic Rotation**: Rotates connections after a set number of messages or time interval
- **Session Management**: Tracks sessions using unique IDs in packet headers
- **Encryption**: AES-256-CBC encryption for all traffic
- **TCP Optimization**: Disables Nagle's algorithm and enables keep-alive
- **UDP Support**: Full UDP forwarding capability
- **Failover**: Automatically uses next connection in pool if current fails
- **Protocol Enum**: Uses strongly-typed Protocol enum instead of boolean flags

## Architecture

```
[Client App] -> [Client Tunnel] -> (Pool of encrypted connections) -> [Server Tunnel] -> [Target Server]
```

### Client Side

- Accepts local connections
- Assigns session IDs to each connection
- Distributes traffic across connection pool
- Rotates connections based on message count or time

### Server Side

- Receives encrypted traffic from multiple pooled connections
- Extracts session ID from headers
- Maintains separate connection to target for each session
- Forwards decrypted traffic to appropriate target

## Building

```bash
make
make install  # Install to /usr/local/bin
make debug    # Build with debug symbols and AddressSanitizer
make clean    # Clean build artifacts
```

## Usage

### TCP Forwarding

Client side:

```bash
./tunnel client 127.0.0.1 8080 server.example.com 9090 target.example.com 443 mysecretkey
```

Server side:

```bash
./tunnel server 0.0.0.0 9090 0.0.0.0 0 127.0.0.1 443 mysecretkey
```

### UDP Forwarding

Client side:

```bash
./tunnel client 127.0.0.1 8080 server.example.com 9090 target.example.com 53 mysecretkey --udp
```

Server side:

```bash
./tunnel server 0.0.0.0 9090 0.0.0.0 0 8.8.8.8 53 mysecretkey --udp
```

## Configuration

The tunnel automatically manages:

- **Pool Size**: 3 connections by default
- **Rotation Interval**: Every 5 seconds or 5 messages
- **Buffer Size**: 64KB for optimal performance
- **Keep-Alive**: Enabled for TCP connections

## Protocol

Each packet contains a header with:

- `session_id` (4 bytes): Unique session identifier
- `data_len` (2 bytes): Length of payload
- `flags` (1 byte): Protocol flags (0x01 for UDP)
- `reserved` (1 byte): Reserved for future use

## File Structure

- `tunnel.hpp` - Base tunnel interface
- `config.hpp` - Configuration constants and structures
- `crypto.hpp/cpp` - Encryption/decryption functionality
- `connection.hpp/cpp` - Individual connection management
- `connection_pool.hpp/cpp` - Pool management with rotation
- `session_store.hpp/cpp` - Session tracking for server side
- `client_tcp_tunnel.hpp/cpp` - TCP client implementation
- `server_tcp_tunnel.hpp/cpp` - TCP server implementation
- `client_udp_tunnel.hpp/cpp` - UDP client implementation
- `server_udp_tunnel.hpp/cpp` - UDP server implementation
- `main.cpp` - Entry point and tunnel selection

## Dependencies

- OpenSSL for encryption
- C++17 compatible compiler
- Linux with epoll support

## Performance Optimizations

- Non-blocking I/O with epoll
- TCP_NODELAY for low latency
- Connection reuse for server-side targets
- Efficient buffer management
- Minimal packet overhead (8 bytes header)

## Security

- AES-256-CBC encryption
- Key derivation using PBKDF
- Session isolation
- No plaintext traffic exposure
