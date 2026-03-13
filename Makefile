BIN_DIR ?= bin
TARGET = $(BIN_DIR)/tiny-tunnel

CXX ?= g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -pthread -I. $(EXTRA_CXXFLAGS)
LDFLAGS = -lcrypto -lssl -pthread $(EXTRA_LDFLAGS)

SOURCES = main.cpp \
		  crypto/aes_crypto.cpp \
		  crypto/xor_crypto.cpp \
		  connection.cpp \
		  connection_pool.cpp \
		  session_store.cpp \
		  tunnels/client_tcp_tunnel.cpp \
		  tunnels/server_tcp_tunnel.cpp \
		  tunnels/client_udp_tunnel.cpp \
		  tunnels/server_udp_tunnel.cpp

HEADERS = config.hpp \
		  crypto/crypto.hpp \
		  crypto/aes_crypto.hpp \
		  crypto/xor_crypto.hpp \
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

OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all build debug install clean _directories

all: build

build: _directories $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

debug: CXXFLAGS += -g -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: build

install: build
	install -m 755 $(TARGET) /usr/local/bin/

clean:
	rm -f $(OBJECTS)
	rm -rf $(BIN_DIR)

_directories:
	@mkdir -p $(BIN_DIR)