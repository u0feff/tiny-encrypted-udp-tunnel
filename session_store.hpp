#ifndef SESSION_STORE_HPP
#define SESSION_STORE_HPP

#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include "connection.hpp"
#include "config.hpp"

class SessionStore
{
private:
    std::unordered_map<uint32_t, std::unique_ptr<Connection>> sessions;
    std::mutex sessions_mutex;
    std::string target_addr;
    int target_port;
    Protocol protocol;

public:
    SessionStore(const std::string &addr, int port, Protocol proto);
    Connection *get_or_create_session(uint32_t session_id);
    void remove_session(uint32_t session_id);
};

#endif