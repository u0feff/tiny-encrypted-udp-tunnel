#ifndef AES_CRYPTO_HPP
#define AES_CRYPTO_HPP

#include <vector>
#include <string>
#include <openssl/evp.h>
#include "crypto.hpp"

class AesCrypto : public Crypto
{
private:
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    unsigned char iv[16];

public:
    AesCrypto(const std::string &password);
    ~AesCrypto();
    std::vector<uint8_t> encrypt(const uint8_t *data, size_t len) override;
    std::vector<uint8_t> decrypt(const uint8_t *data, size_t len) override;
};

#endif