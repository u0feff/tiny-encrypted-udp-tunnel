CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -pthread -I.
LDFLAGS = -lcrypto -lssl -pthread

TARGET = bin/tiny-tunnel

SOURCES = main.cpp \
          crypto/aes_crypto.cpp \
          connection.cpp \
          connection_pool.cpp \
          session_store.cpp \
          tunnels/client_tcp_tunnel.cpp \
          tunnels/server_tcp_tunnel.cpp \
          tunnels/client_udp_tunnel.cpp \
          tunnels/server_udp_tunnel.cpp

OBJECTS = $(SOURCES:.cpp=.o)

HEADERS = config.hpp \
          crypto/crypto.hpp \
          crypto/aes_crypto.hpp \
          connection.hpp \
          connection_pool.hpp \
          session_store.hpp \
          tunnels/tunnel.hpp \
          tunnels/tunnel_header.hpp \
          tunnels/tunnel_direction.hpp \
          tunnels/client_tcp_tunnel.hpp \
          tunnels/server_tcp_tunnel.hpp \
          tunnels/client_udp_tunnel.hpp \
          tunnels/server_udp_tunnel.hpp

.PHONY: all clean install debug test directories

all: directories $(TARGET)

directories:
	@mkdir -p bin

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

debug: CXXFLAGS += -g -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: clean $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -rf bin
