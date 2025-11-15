#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>

constexpr int POOL_SIZE = 3;
constexpr int ROTATE_INTERVAL_MS = 5000;
constexpr int MAX_MESSAGES_PER_CONNECTION = 5;
constexpr int BUFFER_SIZE = 65536;
constexpr int MAX_EVENTS = 64;

enum class Protocol
{
    TCP,
    UDP
};

struct TunnelHeader
{
    uint32_t session_id;
    uint16_t data_len;
    uint8_t flags;
    uint8_t reserved;
};

#endif