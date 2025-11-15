# Tiny Encrypted UDP Tunnel

A lightweight encrypted tunnel for TCP and UDP forwarding with connection pooling to bypass provider restrictions on long-lived connections.

## Features

- **Connection Pooling**: Maintains multiple connections to avoid provider blocks
- **Automatic Rotation**: Rotates connections based on message count or time interval
- **Session Management**: Tracks sessions using unique IDs in packet headers
- **Encryption**: AES-256-CBC encryption for all traffic
- **TCP & UDP Support**: Full forwarding capability for both protocols
- **Automatic Failover**: Uses next connection in pool if current fails

## How It Works

```
[Client App] -> [Client Tunnel] -> (Pool of encrypted connections) -> [Server Tunnel] -> [Target Server]
```

The client tunnel accepts local connections, assigns session IDs, and distributes traffic across a pool of encrypted connections. The server tunnel receives encrypted traffic from multiple pooled connections, extracts session IDs from headers, and forwards decrypted traffic to the appropriate target for each session.

## Building

Requires OpenSSL and a C++17 compatible compiler (Linux with epoll support).

```bash
make
make install  # Install to /usr/local/bin
```

## Usage

### TCP Forwarding

Client:
```bash
./tunnel client 127.0.0.1 8080 server.example.com 9090 target.example.com 443 mysecretkey
```

Server:
```bash
./tunnel server 0.0.0.0 9090 0.0.0.0 0 127.0.0.1 443 mysecretkey
```

### UDP Forwarding

Client:
```bash
./tunnel client 127.0.0.1 8080 server.example.com 9090 target.example.com 53 mysecretkey --udp
```

Server:
```bash
./tunnel server 0.0.0.0 9090 0.0.0.0 0 8.8.8.8 53 mysecretkey --udp
```

## Configuration

The tunnel automatically manages connection pooling with the following defaults:
- **Pool Size**: 3 connections
- **Rotation**: Every 5 seconds or 5 messages
- **Buffer Size**: 64KB

TCP connections use keep-alive and TCP_NODELAY for optimal performance.

## Protocol

Each packet contains an 8-byte header with:
- `session_id` (4 bytes): Unique session identifier
- `data_len` (2 bytes): Payload length
- `flags` (1 byte): Protocol flags (0x01 for UDP)
- `reserved` (1 byte): Reserved for future use

All traffic is encrypted using AES-256-CBC with PBKDF key derivation.

## Security & Performance

**Security:**
- AES-256-CBC encryption with PBKDF key derivation
- Session isolation
- No plaintext traffic exposure

**Performance:**
- Non-blocking I/O with epoll
- Connection reuse for server-side targets
- Minimal packet overhead (8-byte header)
- TCP_NODELAY for low latency
