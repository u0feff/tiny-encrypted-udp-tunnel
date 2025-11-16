#ifndef XOR_CRYPTO_HPP
#define XOR_CRYPTO_HPP

#include <vector>
#include <string>
#include "crypto.hpp"

class XorCrypto : public Crypto
{
private:
    const std::string &password;

public:
    XorCrypto(const std::string &password);
    ~XorCrypto();
    std::vector<uint8_t> encrypt(const uint8_t *data, size_t len) override;
    std::vector<uint8_t> decrypt(const uint8_t *data, size_t len) override;
};

#endif