#include <stdio.h>
#include <string.h>
#include <stdint.h>
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

using namespace std;

map<string, string> mp;

char local_address[100], remote_address[100];
int local_port = -1, remote_port = -1;
char keya[100], keyb[100];
char iv[100];
const int buf_len = 20480;
int use_chacha20 = 0; // 0 = XOR, 1 = ChaCha20

void handler(int num) {
	int status;
	int pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			//printf("The child exit with code %d",WEXITSTATUS(status));
		}
	}
}

// ChaCha20 implementation
// ChaCha20 is a stream cipher designed by D. J. Bernstein
// It's fast, secure, and doesn't use lookup tables (resistant to cache-timing attacks)

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define U32TO8_LITTLE(p, v) \
	do { \
		(p)[0] = (unsigned char)((v)); \
		(p)[1] = (unsigned char)((v) >> 8); \
		(p)[2] = (unsigned char)((v) >> 16); \
		(p)[3] = (unsigned char)((v) >> 24); \
	} while (0)
#define U8TO32_LITTLE(p) \
	(((uint32_t)((p)[0])) | \
	 ((uint32_t)((p)[1]) << 8) | \
	 ((uint32_t)((p)[2]) << 16) | \
	 ((uint32_t)((p)[3]) << 24))

#define CHACHA20_QUARTERROUND(a, b, c, d) \
	do { \
		a += b; d ^= a; d = ROTL32(d, 16); \
		c += d; b ^= c; b = ROTL32(b, 12); \
		a += b; d ^= a; d = ROTL32(d, 8); \
		c += d; b ^= c; b = ROTL32(b, 7); \
	} while (0)

typedef struct {
	uint32_t state[16];
	uint32_t counter;
} chacha20_ctx;

void chacha20_init(chacha20_ctx *ctx, const unsigned char *key, const unsigned char *nonce, uint32_t counter) {
	// Constants "expand 32-byte k"
	ctx->state[0] = 0x61707865;
	ctx->state[1] = 0x3320646e;
	ctx->state[2] = 0x79622d32;
	ctx->state[3] = 0x6b206574;
	
	// Key (32 bytes = 8 words)
	ctx->state[4] = U8TO32_LITTLE(key + 0);
	ctx->state[5] = U8TO32_LITTLE(key + 4);
	ctx->state[6] = U8TO32_LITTLE(key + 8);
	ctx->state[7] = U8TO32_LITTLE(key + 12);
	ctx->state[8] = U8TO32_LITTLE(key + 16);
	ctx->state[9] = U8TO32_LITTLE(key + 20);
	ctx->state[10] = U8TO32_LITTLE(key + 24);
	ctx->state[11] = U8TO32_LITTLE(key + 28);
	
	// Counter
	ctx->state[12] = counter;
	
	// Nonce (12 bytes = 3 words)
	ctx->state[13] = U8TO32_LITTLE(nonce + 0);
	ctx->state[14] = U8TO32_LITTLE(nonce + 4);
	ctx->state[15] = U8TO32_LITTLE(nonce + 8);
	
	ctx->counter = counter;
}

void chacha20_block(chacha20_ctx *ctx, unsigned char *output) {
	uint32_t x[16];
	int i;
	
	// Copy state
	for (i = 0; i < 16; i++) {
		x[i] = ctx->state[i];
	}
	
	// 20 rounds (10 double rounds)
	for (i = 0; i < 10; i++) {
		// Column rounds
		CHACHA20_QUARTERROUND(x[0], x[4], x[8], x[12]);
		CHACHA20_QUARTERROUND(x[1], x[5], x[9], x[13]);
		CHACHA20_QUARTERROUND(x[2], x[6], x[10], x[14]);
		CHACHA20_QUARTERROUND(x[3], x[7], x[11], x[15]);
		// Diagonal rounds
		CHACHA20_QUARTERROUND(x[0], x[5], x[10], x[15]);
		CHACHA20_QUARTERROUND(x[1], x[6], x[11], x[12]);
		CHACHA20_QUARTERROUND(x[2], x[7], x[8], x[13]);
		CHACHA20_QUARTERROUND(x[3], x[4], x[9], x[14]);
	}
	
	// Add state to x
	for (i = 0; i < 16; i++) {
		x[i] += ctx->state[i];
	}
	
	// Convert to bytes
	for (i = 0; i < 16; i++) {
		U32TO8_LITTLE(output + (i * 4), x[i]);
	}
	
	// Increment counter
	ctx->state[12]++;
}

void chacha20_encrypt_decrypt(unsigned char *data, size_t len, const unsigned char *key, const unsigned char *nonce) {
	chacha20_ctx ctx;
	unsigned char keystream[64];
	size_t i, j;
	
	chacha20_init(&ctx, key, nonce, 0);
	
	for (i = 0; i < len; i += 64) {
		chacha20_block(&ctx, keystream);
		
		size_t block_len = (len - i > 64) ? 64 : (len - i);
		for (j = 0; j < block_len; j++) {
			data[i + j] ^= keystream[j];
		}
	}
}

// Derive a 32-byte key and 12-byte nonce from password
void chacha20_derive_key_nonce(const char *password, unsigned char *key, unsigned char *nonce) {
	// Simple key derivation: hash password multiple times
	// For production, use a proper KDF like PBKDF2 or Argon2
	size_t pass_len = strlen(password);
	unsigned char temp[64];
	memset(temp, 0, sizeof(temp));
	
	// Copy password and repeat to fill buffer
	for (size_t i = 0; i < 64; i++) {
		temp[i] = password[i % pass_len] ^ (i & 0xFF);
	}
	
	// Simple mixing - XOR fold and rotate
	for (int round = 0; round < 16; round++) {
		for (size_t i = 0; i < 32; i++) {
			temp[i] ^= temp[i + 32];
			temp[i] = (temp[i] << 3) | (temp[i] >> 5);
		}
		for (size_t i = 0; i < 64; i++) {
			temp[i] ^= password[i % pass_len];
		}
	}
	
	// First 32 bytes = key, next 12 bytes = nonce
	memcpy(key, temp, 32);
	memcpy(nonce, temp + 32, 12);
}

void encrypt(char * input, int len, char *key) {
	if (use_chacha20) {
		// ChaCha20 encryption
		unsigned char chacha_key[32];
		unsigned char chacha_nonce[12];
		chacha20_derive_key_nonce(key, chacha_key, chacha_nonce);
		chacha20_encrypt_decrypt((unsigned char*)input, len, chacha_key, chacha_nonce);
	} else {
		// XOR encryption
		int i, j;
		for (i = 0, j = 0; i < len; i++, j++) {
			if (key[j] == 0)
				j = 0;
			input[i] ^= key[j];
		}
	}
}

void decrypt(char * input, int len, char *key) {
	if (use_chacha20) {
		// ChaCha20 decryption (same as encryption for stream ciphers)
		unsigned char chacha_key[32];
		unsigned char chacha_nonce[12];
		chacha20_derive_key_nonce(key, chacha_key, chacha_nonce);
		chacha20_encrypt_decrypt((unsigned char*)input, len, chacha_key, chacha_nonce);
	} else {
		// XOR decryption
		int i, j;
		for (i = 0, j = 0; i < len; i++, j++) {
			if (key[j] == 0)
				j = 0;
			input[i] ^= key[j];
		}
	}
}

// Add random padding to the beginning of data
// Returns new length after adding padding
// Format: [1 byte: padding_len][padding_len bytes: random data][original data]
int add_padding(char *data, int data_len, char *output, int max_output_len) {
	// Read random byte for padding length (0-255)
	unsigned char padding_len;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		// If urandom fails, use a simpler random
		padding_len = rand() % 256;
	} else {
		read(fd, &padding_len, 1);
		close(fd);
	}
	
	// Check if we have enough space
	int total_len = 1 + padding_len + data_len;
	if (total_len > max_output_len) {
		// Reduce padding to fit
		padding_len = max_output_len - 1 - data_len;
		if (padding_len < 0) padding_len = 0;
		total_len = 1 + padding_len + data_len;
	}
	
	// Write padding length as first byte
	output[0] = padding_len;
	
	// Write random padding
	if (padding_len > 0) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			// Fallback to rand()
			for (int i = 0; i < padding_len; i++) {
				output[1 + i] = rand() % 256;
			}
		} else {
			read(fd, output + 1, padding_len);
			close(fd);
		}
	}
	
	// Copy original data after padding
	memcpy(output + 1 + padding_len, data, data_len);
	
	return total_len;
}

// Remove padding from the beginning of data
// Returns new length after removing padding, or -1 on error
int remove_padding(char *data, int data_len) {
	if (data_len < 1) {
		return -1; // Invalid: need at least 1 byte for padding length
	}
	
	unsigned char padding_len = (unsigned char)data[0];
	
	// Check if padding length is valid
	if (1 + padding_len > data_len) {
		return -1; // Invalid: padding extends beyond data
	}
	
	// Move actual data to beginning of buffer
	int actual_data_len = data_len - 1 - padding_len;
	memmove(data, data + 1 + padding_len, actual_data_len);
	
	return actual_data_len;
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

	printf("argc=%d ", argc);
	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	printf("\n");
	memset(keya, 0, sizeof(keya));
	memset(keyb, 0, sizeof(keyb));
	memset(iv, 0, sizeof(iv));
	strcpy(iv, "1234567890abcdef");
	if (argc == 1) {
		printf("proc -l [adress:]port -r [adress:]port  [-a passwd] [-b passwd] [-c]\n");
		printf("  -c: use ChaCha20 encryption (default: XOR)\n");
		return -1;
	}
	int no_l = 1, no_r = 1;
	while ((opt = getopt(argc, argv, "l:r:a:b:ch")) != -1) {
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
		case 'c':
			use_chacha20 = 1;
			printf("Using ChaCha20 encryption\n");
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
			decrypt(buf, recv_len, keya);
			int new_len = remove_padding(buf, recv_len);
			if (new_len < 0) {
				printf("Error: invalid padding\n");
				continue;
			}
			recv_len = new_len;
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

			char temp_buf[buf_len]; // temporary buffer for padding operations

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
				int padded_len = add_padding(buf, recv_len, temp_buf, buf_len);
				memcpy(buf, temp_buf, padded_len);
				recv_len = padded_len;
				encrypt(buf, recv_len, keyb);
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
							decrypt(buf, recv_len2, keya);
							int new_len = remove_padding(buf, recv_len2);
							if (new_len < 0) {
								printf("Error: invalid padding @1\n");
								continue;
							}
							recv_len2 = new_len;
						}
						buf[recv_len2] = 0;
						printf("len %ld received from child@1\n", recv_len2);
						if (keyb[0]) {
							int padded_len = add_padding(buf, recv_len2, temp_buf, buf_len);
							memcpy(buf, temp_buf, padded_len);
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
							decrypt(buf, recv_len2, keyb);
							int new_len = remove_padding(buf, recv_len2);
							if (new_len < 0) {
								printf("Error: invalid padding @2\n");
								continue;
							}
							recv_len2 = new_len;
						}
						buf[recv_len2] = 0;
						printf("len %ld received from child@2\n", recv_len2);
						if (keya[0]) {
							int padded_len = add_padding(buf, recv_len2, temp_buf, buf_len);
							memcpy(buf, temp_buf, padded_len);
							recv_len2 = padded_len;
							encrypt(buf, recv_len2, keya);
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
