#ifndef TUNNEL_HEADER_HPP
#define TUNNEL_HEADER_HPP

#include <cstdint>

struct TunnelHeader
{
    uint32_t session_id;
    uint16_t data_len;
    uint8_t flags;
    uint8_t direction; // 0 = request, 1 = response
};

#endif