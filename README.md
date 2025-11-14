# tiny-encrypted-udp-tunnel
tiny singlefile encrypted udp tunnel/forwarder

# keywords
encrypted,udp port forwarder,udp tunnel,openvpn being blocked,hide openvpn traffic

# background 
this program is originally designed for tunneling udp mode openvpn.(though it can be used for forwarding/tunneling any udp based protocol)

as we know,openvpn uses encryption for authentication and it encrypts the data it carrys.

however,it doesnt encrypt the handshake and control flow.in other words,it doenst aim at prevent itself from being detected by firewalls.

while openssh provided an easy-to-use tunnel feature,it doesnt support tunneling udp.ssh aslo doesnt prevent itself from being detected by firewalls.

this program allow you to do encrypted tunneling so that firewalls wont be able to know the existence of a openvpn connection.

has been stablely running for years on my server and router. 

linux x64 and mips_ar71xx binaries have already been built.

# usage
this program is essentially a port forwarder which allows you to use a key for encryption/decryption at either side.if you use a pair of them,one at local host,the other at remote host,they form a tunnel together.

forward -l [adressA:]portA -r [adressB:]portB  [-a passwdA] [-b passwdB] [-c] [-p pool_size] [-m rotation_messages]

after being started,this program will forward all packet received from adressA:portA to adressB:portB. and all packet received back from adressB:portB will be forward back to adressA:portA. it can handle multiple udp connection.

basic option:

-l -r option are required. -l indicates the local adress&port, -r indicates the remote adress&port.

adressA and adressB are optional,if adressA or adressB are ommited,127.0.0.1 will be used by default.only ipv4 adress has been tested.


encryption option:

-a and -b are optional.

if -a is used ,all packet goes into adressA:portA will be decrypted by passwdA,and all packet goes out from adressA:portA will be encrypted by passwdA.if -a is omited,data goes into/out adressA:portA will not be encrypted/decrypted.

if -b is used ,all packet goes into adressB:portB will be decrypted by passwdB,and all packet goes out from adressB:portB will be encrypted by passwdB.if -b is omited,data goes into/out adressB:portB will not be encrypted/decrypted.

-c (optional): use ChaCha20 encryption instead of XOR. Provides stronger cryptographic security. Both sides must use the same encryption method.

connection pooling option (anti-blocking feature):

-p (optional): enable connection pooling with specified pool size (default: 3, range: 1-10). This creates multiple UDP connections that rotate to avoid provider blocking after prolonged sessions.

-m (optional): rotate to next connection in pool after this many messages (default: 5, set to 0 to disable rotation). When a connection exceeds this limit, it will be closed and a new one created on a different local port.




# example
assume an udp mode openvpn server is running at 44.55.66.77:9000

## Example 1: Using XOR encryption (default, legacy)
run this at sever side at 44.55.66.77:
./forward -l0.0.0.0:9001 -r127.0.0.1:9000 -a'abcd' > /dev/null &

run this at client side:
./forward -l 127.0.0.1:9002 -r 44.55.66.77:9001 -b 'abcd' >/dev/null&

## Example 2: Using ChaCha20 encryption (recommended)
run this at sever side at 44.55.66.77:
./forward -l0.0.0.0:9001 -r127.0.0.1:9000 -a'abcd' -c -p 3 > /dev/null &

run this at client side:
./forward -l 127.0.0.1:9002 -r 44.55.66.77:9001 -b 'abcd' -c -p 3 >/dev/null&

## Example 3: Using connection pooling to avoid blocking
If your provider blocks long sessions after several messages, use connection pooling:

Client side (with connection pool):
./forward -l 127.0.0.1:9002 -r 44.55.66.77:9001 -b 'abcd' -c -p 3 -m 5 >/dev/null&

Server side (with session tracking):
./forward -l0.0.0.0:9001 -r127.0.0.1:9000 -a'abcd' -c -p 3 > /dev/null &

This creates a pool of 3 connections that rotate after every 5 messages. Each rotation:
- Closes the current connection
- Opens a new connection on a different local port
- Maintains session continuity via session ID headers
- Falls back to next connection if one fails

now,configure you openvpn client to connect to 127.0.0.1:9002

dataflow:


                  client computer                                                           server computer (44.55.66.77)
    +---------------------------------------------+                           +------------------------------------------------+
    |   openvpn                                   |                           |                              openvpn server    |
    |   client                      forwarder     |                           |    forwarder                    daemon         |
    | +-----------+               +------------+  |                           |   +-----------+                +------------+  |
    | |           |r              |            |r |                           |   |           |r               |            |  |
    | |           |a             9|            |a |                           |  9|           |a              9|            |  |
    | |           |n             0|            |n |                           |  0|           |n              0|            |  |
    | |           |d <-------->  0|            |d<-----------------------------> 0|           |d  <-------->  0|            |  |
    | |           |o(unencrypted)2|            |o |    (encrypted channel     |  1|           |o (unencrypted)0|            |  |
    | |           |m              |            |m |      by key 'abcd')       |   |           |m               |            |  |
    | +-----------+               +------------+  |                           |   +-----------+                +------------+  |
    |                                             |                           |                                                |
    +---------------------------------------------+                           +------------------------------------------------+



# method of encryption
this program supports two encryption methods:

## XOR (default, legacy)
currently the default encryption uses XOR. mainly bc i use a mips_ar71xx router as client.router's cpu is slow,i personally need fast processing speed.and XOR is enough for fooling the firewall i have encountered.

## ChaCha20 (recommended for stronger encryption)
ChaCha20 is a modern stream cipher designed by D. J. Bernstein. It provides:
- **Strong cryptographic security**: Much stronger than XOR
- **Lightweight and fast**: Optimized for software implementation, no lookup tables needed
- **Less common**: Helps avoid detection by making traffic patterns less recognizable
- **Cache-timing attack resistant**: No table lookups means consistent timing

To use ChaCha20 encryption, add the `-c` flag when starting the forwarder:
```
./forward -l0.0.0.0:9001 -r127.0.0.1:9000 -a'abcd' -c > /dev/null &
```

**Important**: Both sides of the tunnel must use the same encryption method. If one side uses `-c`, the other side must also use `-c`.

nevertheless,you can easily integrate your own encrytion algotirhm into this program if you need different encryption.all you need to do is to rewrite 'void encrypt(char * input,int len,char *key)' and 'void decrypt(char * input,int len,char *key)'.

# traffic obfuscation

## STUN-like padding
When encryption is enabled (using either `-a` or `-b` flag), the program automatically adds padding that makes the encrypted traffic look like WebRTC STUN (Session Traversal Utilities for NAT) packets. This helps the tunnel traffic blend in with legitimate WebRTC traffic, making it harder for firewalls to detect and block.

**STUN Header Structure:**
Each encrypted packet is wrapped with a 20-byte STUN header containing:
- Message Type: 0x0001 (STUN Binding Request)
- Message Length: Size of the encrypted payload
- Magic Cookie: 0x2112A442 (standard STUN identifier)
- Transaction ID: 12 random bytes (with padding metadata)

The STUN header remains unencrypted so that Deep Packet Inspection (DPI) systems will see what appears to be legitimate STUN/WebRTC traffic, while the actual data payload is encrypted underneath.

This feature is automatic when using encryption - no additional flags needed.

# connection pooling

## Overview
Some Internet providers block or throttle long-lasting UDP sessions, often after a certain number of packets or time period. Connection pooling helps bypass this limitation by rotating through multiple connections.

## How It Works
When connection pooling is enabled with the `-p` flag:

1. **Client Side**: Creates a pool of N connections (default 3) and rotates through them
   - Each connection uses a different local port
   - After M messages (default 5, configurable with `-m`), the connection rotates to the next in the pool
   - The old connection is closed and a new one is created on a different local port
   - If a connection fails, it automatically falls back to the next connection in the pool
   - Session ID headers are added to maintain session continuity

2. **Server Side**: Tracks sessions by session ID
   - Receives packets with session ID headers
   - Routes packets to the correct backend connection based on session ID
   - Maintains session state across connection rotations
   - Cleans up stale sessions automatically

## Session ID Header
When pooling is enabled, an 8-byte header is added to each packet:
- 4 bytes: Session ID (unique identifier for this client session)
- 4 bytes: Message counter (increments with each message)

This header is added **before** encryption and **after** decryption, allowing the server to route packets correctly even when connections rotate.

## Benefits
- **Avoids blocking**: By rotating connections, prevents provider detection of long sessions
- **Resilience**: Automatically recovers from connection failures
- **Session continuity**: Maintains session state across connection changes
- **Configurable**: Adjust pool size and rotation frequency based on your needs

## Usage Notes
- Both client and server should use the same pool settings for optimal performance
- Adjust rotation messages (`-m`) based on when your provider typically blocks
- Pool size (`-p`) should be small (3-5) to minimize resource usage
- Works with both XOR and ChaCha20 encryption
