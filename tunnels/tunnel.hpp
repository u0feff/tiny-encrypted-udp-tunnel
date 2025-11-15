#ifndef TUNNEL_HPP
#define TUNNEL_HPP

#include <atomic>
#include <string>

class Tunnel
{
protected:
    std::atomic<bool> running{true};

public:
    virtual ~Tunnel() = default;
    virtual void run() = 0;
    virtual void stop() { running = false; }
};

#endif