#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdexcept>
#include <vector>

// Encrypts the given plaintext using AES-256-CBC and the provided key
std::string encryptPassword(const std::string& plaintext, const std::string& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create a new cipher context
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH); // Allocate space for ciphertext
    int len = 0, ciphertext_len = 0;

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption initialization failed");
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption update failed");
    }
    ciphertext_len = len;

    // Finalize the encryption operation
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);  // Free the cipher context

    return std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len); // Return the encrypted data as a string
}

// Decrypts the given ciphertext using AES-256-CBC and the provided key
std::string decryptPassword(const std::string& ciphertext, const std::string& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create a new cipher context
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH); // Allocate space for plaintext
    int len = 0, plaintext_len = 0;

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption initialization failed");
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption update failed");
    }
    plaintext_len = len;

    // Finalize the decryption operation
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);  // Free the cipher context

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len); // Return the decrypted data as a string
}
