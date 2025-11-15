#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

Crypto::Crypto(const std::string &password)
{
    ctx = EVP_CIPHER_CTX_new();
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                   reinterpret_cast<const unsigned char *>(password.c_str()),
                   password.length(), 1, key, iv);
}

Crypto::~Crypto()
{
    EVP_CIPHER_CTX_free(ctx);
}

std::vector<uint8_t> Crypto::encrypt(const uint8_t *data, size_t len)
{
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<uint8_t> encrypted(len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int out_len = 0;
    int final_len = 0;

    EVP_EncryptUpdate(ctx, encrypted.data(), &out_len, data, len);
    EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &final_len);

    encrypted.resize(out_len + final_len);
    return encrypted;
}

std::vector<uint8_t> Crypto::decrypt(const uint8_t *data, size_t len)
{
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<uint8_t> decrypted(len);
    int out_len = 0;
    int final_len = 0;

    EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, data, len);
    EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len);

    decrypted.resize(out_len + final_len);
    return decrypted;
}