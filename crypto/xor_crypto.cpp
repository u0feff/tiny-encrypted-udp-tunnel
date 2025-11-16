#include "xor_crypto.hpp"

XorCrypto::XorCrypto(const std::string &password) : password(password)
{
}

XorCrypto::~XorCrypto()
{
}

std::vector<uint8_t> XorCrypto::encrypt(const uint8_t *data, size_t len)
{
    std::vector<uint8_t> encrypted(len);

    size_t i, j;
    for (i = 0, j = 0; i < len; i++, j++)
    {
        if (j >= password.length())
            j = 0;

        encrypted[i] = data[i] ^ password[j];
    }

    return encrypted;
}

std::vector<uint8_t> XorCrypto::decrypt(const uint8_t *data, size_t len)
{
    std::vector<uint8_t> decrypted(len);

    size_t i, j;
    for (i = 0, j = 0; i < len; i++, j++)
    {
        if (j >= password.length())
            j = 0;

        decrypted[i] = data[i] ^ password[j];
    }

    return decrypted;
}