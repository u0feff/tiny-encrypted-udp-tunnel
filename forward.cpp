#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>
#include <netdb.h>
#include <ctype.h>
#include <map>
#include <string>
#include <vector>
#include <time.h>

using namespace std;

map<string, string> mp;

char local_address[100], remote_address[100];
int local_port = -1, remote_port = -1;
char keya[100], keyb[100];
char iv[100];
const int buf_len = 20480;
int urandom_fd = -1;

void handler(int num) {
	int status;
	int pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			//printf("The child exit with code %d",WEXITSTATUS(status));
		}
	}
}

// Initialize random source
void init_random() {
	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		// Fallback to srand if /dev/urandom is not available
		srand(time(NULL) ^ getpid());
	}
}

// Get random byte
unsigned char get_random_byte() {
	unsigned char byte;
	if (urandom_fd >= 0) {
		if (read(urandom_fd, &byte, 1) != 1) {
			// Fallback to rand()
			byte = rand() & 0xFF;
		}
	} else {
		byte = rand() & 0xFF;
	}
	return byte;
}

// Add random padding BEFORE encrypted data
// Format: [padding_length:1byte][random_padding][encrypted_data]
// The padding_length and padding are unencrypted
int add_padding(char *input, int len, char *output, int max_len) {
	if (len >= max_len - 1) {
		// Not enough space for padding header, just copy data
		memcpy(output, input, len);
		return len;
	}
	
	// Random padding length (0-255 bytes)
	unsigned char padding_len = get_random_byte();
	
	// Make sure we don't exceed buffer
	int available = max_len - len - 1;
	if (padding_len > available) {
		padding_len = available;
	}
	
	// Format: [padding_len:1byte][random padding][encrypted_data]
	output[0] = padding_len;
	
	// Add random padding bytes
	for (int i = 0; i < padding_len; i++) {
		output[1 + i] = get_random_byte();
	}
	
	// Copy encrypted data after padding
	memcpy(output + 1 + padding_len, input, len);
	
	return 1 + padding_len + len;
}

// Remove padding from the message
// Returns the actual data length (without padding header and padding)
int remove_padding(char *input, int len, char *output, int max_len) {
	if (len < 1) {
		return -1;
	}
	
	// First byte is padding length
	unsigned char padding_len = (unsigned char)input[0];
	
	// Calculate encrypted data length
	int data_len = len - 1 - padding_len;
	
	// Sanity check
	if (data_len < 0 || data_len > max_len) {
		// Invalid padding length
		return -1;
	}
	
	// Copy encrypted data (skip padding_len byte and padding bytes)
	memcpy(output, input + 1 + padding_len, data_len);
	return data_len;
}

void encrypt(char * input, int len, char *key) {
	int i, j;
	for (i = 0, j = 0; i < len; i++, j++) {
		if (key[j] == 0)
			j = 0;
		input[i] ^= key[j];
	}
}

void decrypt(char * input, int len, char *key) {
	int i, j;
	for (i = 0, j = 0; i < len; i++, j++) {
		if (key[j] == 0)
			j = 0;
		input[i] ^= key[j];
	}
}

void setnonblocking(int sock) {
	int opts;
	opts = fcntl(sock, F_GETFL);

	if (opts < 0) {
		perror("fcntl(sock,GETFL)");
		exit(1);
	}

	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
		perror("fcntl(sock,SETFL,opts)");
		exit(1);
	}
}

// Helper function to resolve address (IPv4 or IPv6)
int resolve_addr(const char* addr, int port, struct sockaddr_storage* ss, socklen_t* slen, int* family) {
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // allow IPv4 or IPv6
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%d", port);
	int r = getaddrinfo(addr, portstr, &hints, &res);
	if (r != 0) {
		fprintf(stderr, "getaddrinfo failed for %s:%d %s\n", addr, port, gai_strerror(r));
		return -1;
	}
	memcpy(ss, res->ai_addr, res->ai_addrlen);
	*slen = res->ai_addrlen;
	if (family) *family = res->ai_family;
	freeaddrinfo(res);
	return 0;
}

int parse_addr_port(const char* input, char* address, size_t address_size, int* port) {
    *port = -1;
    if (!input || !address || address_size == 0) return -1;

    // Handle [IPv6]:port syntax first
    if (input[0] == '[') {
        const char* end = strchr(input, ']');
        if (!end) return -1; // Malformed
        size_t len = end - (input + 1);
        if (len >= address_size) return -1;
        strncpy(address, input + 1, len);
        address[len] = '\0';
        if (end[1] == ':' && end[2]) {
            *port = atoi(end + 2);
        }
        return 0;
    }

    // Find last ':' for port separation, but only if there are digits after
    const char* last_colon = strrchr(input, ':');
    if (last_colon && last_colon[1] && strspn(last_colon + 1, "0123456789") == strlen(last_colon + 1)) {
        // There is a port
        size_t len = last_colon - input;
        if (len >= address_size) return -1;
        strncpy(address, input, len);
        address[len] = '\0';
        *port = atoi(last_colon + 1);
        return 0;
    }

    // Otherwise, whole input is address
    if (strlen(input) >= address_size) return -1;
    strcpy(address, input);
    *port = -1;
    return 0;
}

int main(int argc, char *argv[]) {
	int i, j, k;
	int opt;
	signal(SIGCHLD, handler);
	init_random();

	printf("argc=%d ", argc);
	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	printf("\n");
	memset(keya, 0, sizeof(keya));
	memset(keyb, 0, sizeof(keyb));
	memset(iv, 0, sizeof(iv));
	strcpy(iv, "1234567890abcdef");
	if (argc == 1) {
		printf("proc -l [adress:]port -r [adress:]port  [-a passwd] [-b passwd]\n");
		return -1;
	}
	int no_l = 1, no_r = 1;
	while ((opt = getopt(argc, argv, "l:r:a:b:h")) != -1) {
		switch (opt) {
		case 'l':
			no_l = 0;

			if (parse_addr_port(optarg, local_address, sizeof(local_address), &local_port) == 0) {
				fprintf(stderr, "local %s -> %s:%d\n", optarg, local_address, local_port);
			} else {
				printf("error parsing local address:port\n");
			}
			break;
		case 'r':
			no_r = 0;

			if (parse_addr_port(optarg, remote_address, sizeof(remote_address), &remote_port) == 0) {
				fprintf(stderr, "remote %s -> %s:%d\n", optarg, remote_address, remote_port);
			} else {
				printf("error parsing remote address:port\n");
			}
			break;
		case 'a':
			strcpy(keya, optarg);
			break;
		case 'b':
			strcpy(keyb, optarg);
			break;
		case 'h':
			break;
		default:
			printf("ignore unknown <%s>", optopt);
		}
	}

	if (no_l)
		printf("error: -i not found\n");
	if (no_r)
		printf("error: -o not found\n");
	if (no_l || no_r) {
		exit(-1);
	}

	struct sockaddr_storage local_me, local_other;
	socklen_t slen_me, slen_other;
	int addr_family = AF_UNSPEC;

	// resolve local address
	if (resolve_addr(local_address, local_port, &local_me, &slen_me, &addr_family) != 0) {
		fprintf(stderr, "Failed to resolve local address\n");
		exit(1);
	}

	int local_listen_fd = socket(addr_family, SOCK_DGRAM, 0);
	if (local_listen_fd < 0) {
		perror("socket");
		exit(1);
	}
	int yes = 1;
	setsockopt(local_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	char buf[buf_len];
	char buf2[buf_len]; // Buffer for data after padding removal
	socklen_t slen = slen_me;
	if (bind(local_listen_fd, (struct sockaddr*) &local_me, slen_me) == -1) {
		printf("socket bind error");
		exit(1);
	}
	while (1) {
		socklen_t recv_len;
		memset(&local_other, 0, sizeof(local_other));
		slen_other = sizeof(local_other);
		if ((recv_len = recvfrom(local_listen_fd, buf, buf_len, 0,
				(struct sockaddr *) &local_other, &slen_other)) == -1) {
			printf("recv_from error");
			exit(1);
		}

		char addrstr[INET6_ADDRSTRLEN];
		void *sin_addr = NULL;
		int port = 0;
		if (((struct sockaddr *)&local_other)->sa_family == AF_INET) {
			sin_addr = &((struct sockaddr_in *)&local_other)->sin_addr;
			port = ntohs(((struct sockaddr_in *)&local_other)->sin_port);
		} else {
			sin_addr = &((struct sockaddr_in6 *)&local_other)->sin6_addr;
			port = ntohs(((struct sockaddr_in6 *)&local_other)->sin6_port);
		}
		inet_ntop(((struct sockaddr *)&local_other)->sa_family, sin_addr, addrstr, sizeof(addrstr));
		printf("Received packet from %s:%d\n", addrstr, port);

		if (keya[0]) {
			// Remove padding first, then decrypt
			int actual_len = remove_padding(buf, recv_len, buf2, buf_len);
			if (actual_len < 0) {
				printf("Error removing padding\n");
				continue;
			}
			memcpy(buf, buf2, actual_len);
			recv_len = actual_len;
			decrypt(buf, recv_len, keya);
		}
		buf[recv_len] = 0;
		printf("recv_len: %d\n", (int)recv_len);
		fflush(stdout);

		// prepare for reply
		struct sockaddr_storage reply_me;
		socklen_t reply_me_len;
		int local_fd = socket(addr_family, SOCK_DGRAM, 0);
		if (local_fd < 0) {
			perror("socket");
			exit(1);
		}
		setsockopt(local_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		// bind to the same local address/port as the listening socket
		memcpy(&reply_me, &local_me, sizeof(local_me)); 
		reply_me_len = slen_me;
		if (bind(local_fd, (struct sockaddr*) &reply_me, reply_me_len) == -1) {
			printf("socket bind error in child");
			exit(1);
		}
		int ret = connect(local_fd, (struct sockaddr *) &local_other, slen_other);
		if (fork() == 0) { // child
			if (ret != 0) {
				printf("connect return %d @1\n", ret);
				exit(1);
			}
			close(local_listen_fd);

			struct sockaddr_storage remote_other;
			socklen_t remote_other_len;
			int remote_family = AF_UNSPEC;
			if (resolve_addr(remote_address, remote_port, &remote_other, &remote_other_len, &remote_family) != 0) {
				fprintf(stderr, "Failed to resolve remote address\n");
				exit(1);
			}
			int remote_fd = socket(remote_family, SOCK_DGRAM, 0);
			if (remote_fd < 0) {
				perror("socket");
				exit(1);
			}
			ret = connect(remote_fd, (struct sockaddr *) &remote_other, remote_other_len);
			if (ret != 0) {
				printf("connect return %d @2\n", ret);
				exit(1);
			}

			if (keyb[0]) {
				// Encrypt first, then add unencrypted padding after
				encrypt(buf, recv_len, keyb);
				int padded_len = add_padding(buf, recv_len, buf2, buf_len);
				memcpy(buf, buf2, padded_len);
				recv_len = padded_len;
			}
			ret = send(remote_fd, buf, recv_len, 0);
			printf("send return %d\n", ret);
			if (ret < 0)
				exit(-1);

			setnonblocking(remote_fd);
			setnonblocking(local_fd);
			int epollfd = epoll_create1(0);
			const int max_events = 4096;
			struct epoll_event ev, events[max_events];
			if (epollfd < 0) {
				printf("epoll return %d\n", epollfd);
				exit(-1);
			}
			ev.events = EPOLLIN;
			ev.data.fd = local_fd;
			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, local_fd, &ev);
			if (ret < 0) {
				printf("epoll_ctl return %d\n", ret);
				exit(-1);
			}
			ev.events = EPOLLIN;
			ev.data.fd = remote_fd;
			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, remote_fd, &ev);
			if (ret < 0) {
				printf("epoll_ctl return %d\n", ret);
				exit(-1);
			}
			for (;;) {
				int nfds = epoll_wait(epollfd, events, max_events, 180 * 1000);
				if (nfds <= 0) {
					printf("epoll_wait return %d\n", nfds);
					exit(-1);
				}
				int n;
				for (n = 0; n < nfds; ++n) {
					if (events[n].data.fd == local_fd) {
						ssize_t recv_len2 = recv(local_fd, buf, buf_len, 0);
						if (recv_len2 < 0) {
							printf("recv return %ld @1", recv_len2);
							exit(1);
						}
						if (keya[0]) {
							// Remove padding first, then decrypt
							int actual_len = remove_padding(buf, recv_len2, buf2, buf_len);
							if (actual_len < 0) {
								printf("Error removing padding @1\n");
								continue;
							}
							memcpy(buf, buf2, actual_len);
							recv_len2 = actual_len;
							decrypt(buf, recv_len2, keya);
						}
						buf[recv_len2] = 0;
						printf("len %ld received from child@1\n", recv_len2);
						if (keyb[0]) {
							// Encrypt first, then add unencrypted padding
							encrypt(buf, recv_len2, keyb);
							int padded_len = add_padding(buf, recv_len2, buf2, buf_len);
							memcpy(buf, buf2, padded_len);
							recv_len2 = padded_len;
							encrypt(buf, recv_len2, keyb);
						}
						ret = send(remote_fd, buf, recv_len2, 0);
						if (ret < 0) {
							printf("send return %d at @1", ret);
							exit(1);
						}
						printf("send return %d @1\n", ret);
					} else if (events[n].data.fd == remote_fd) {
						ssize_t recv_len2 = recv(remote_fd, buf, buf_len, 0);
						if (recv_len2 < 0) {
							printf("recv return -1 @2");
							exit(1);
						}
						if (keyb[0]) {
							// Remove padding first, then decrypt
							int actual_len = remove_padding(buf, recv_len2, buf2, buf_len);
							if (actual_len < 0) {
								printf("Error removing padding @2\n");
								continue;
							}
							memcpy(buf, buf2, actual_len);
							recv_len2 = actual_len;
							decrypt(buf, recv_len2, keyb);
						}
						buf[recv_len2] = 0;
						printf("len %ld received from child@2\n", recv_len2);
						if (keya[0]) {
							// Encrypt first, then add unencrypted padding
							encrypt(buf, recv_len2, keya);
							int padded_len = add_padding(buf, recv_len2, buf2, buf_len);
							memcpy(buf, buf2, padded_len);
							recv_len2 = padded_len;
						}
						ret = send(local_fd, buf, recv_len2, 0);
						if (ret < 0) {
							printf("send return %d @2", ret);
							exit(1);
						}
						printf("send return %d @2\n", ret);
					}
				}
			}
			exit(0);
		} else {
			close(local_fd);
		}
	}
	return 0;
}
