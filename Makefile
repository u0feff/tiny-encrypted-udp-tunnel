CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -pthread
LDFLAGS = -lcrypto -lssl -pthread

TARGET = tiny-tunnel

SOURCES = main.cpp \
          crypto.cpp \
          connection.cpp \
          connection_pool.cpp \
          session_store.cpp \
          client_tcp_tunnel.cpp \
          server_tcp_tunnel.cpp \
          client_udp_tunnel.cpp \
          server_udp_tunnel.cpp

OBJECTS = $(SOURCES:.cpp=.o)

HEADERS = tunnel.hpp \
          config.hpp \
          crypto.hpp \
          connection.hpp \
          connection_pool.hpp \
          session_store.hpp \
          client_tcp_tunnel.hpp \
          server_tcp_tunnel.hpp \
          client_udp_tunnel.hpp \
          server_udp_tunnel.hpp

.PHONY: all clean install debug test

all: $(TARGET)

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
