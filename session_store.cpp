#include "session_store.hpp"

SessionStore::SessionStore(const std::string &addr, int port, Protocol proto)
    : target_addr(addr), target_port(port), protocol(proto) {}

Connection *SessionStore::get_or_create_session(uint32_t session_id)
{
    std::lock_guard<std::mutex> lock(sessions_mutex);

    auto it = sessions.find(session_id);
    if (it == sessions.end())
    {
        sessions[session_id] = std::make_unique<Connection>(target_addr, target_port, protocol);
    }
    return sessions[session_id].get();
}

void SessionStore::remove_session(uint32_t session_id)
{
    std::lock_guard<std::mutex> lock(sessions_mutex);
    sessions.erase(session_id);
}