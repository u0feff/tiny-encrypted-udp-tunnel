#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <string>
#include <openssl/evp.h>

class Crypto
{
private:
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    unsigned char iv[16];

public:
    Crypto(const std::string &password);
    ~Crypto();
    std::vector<uint8_t> encrypt(const uint8_t *data, size_t len);
    std::vector<uint8_t> decrypt(const uint8_t *data, size_t len);
};

#endif