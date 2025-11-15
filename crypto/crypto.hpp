#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <string>
#include <openssl/evp.h>

class Crypto
{
public:
    virtual ~Crypto() = default;
    virtual std::vector<uint8_t> encrypt(const uint8_t *data, size_t len) = 0;
    virtual std::vector<uint8_t> decrypt(const uint8_t *data, size_t len) = 0;
};

#endif