#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

// Function to encrypt plaintext using AES-256-CBC
std::string Encryption::encrypt(const std::string& plaintext, const std::string& key) {
    // Create new encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        // Throw error if the context creation fails
        throw std::runtime_error("Failed to create encryption context");
    }

    // Generate random initialization vector (IV)
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        // Clean up context and throw error if IV generation fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    // Ensure key is correct length (32 bytes for AES-256)
    unsigned char keyBytes[32];
    std::memset(keyBytes, 0, 32);
    std::memcpy(keyBytes, key.data(), std::min(key.size(), sizeof(keyBytes))); // Copy the key

    // Initialize encryption operation with AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, keyBytes, iv)) {
        // Clean up context and throw error if initialization fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    // Prepare buffer to hold the ciphertext (encrypted data)
    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE); // Ensure enough space for the ciphertext

    int len; // This will store length of the ciphertext after each operation

    // Perform the encryption
    if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size())) {
        // Clean upcontext and throw error if encryption fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }

    int ciphertext_len = len; // Store length of the ciphertext so far

    // Finalize encryption (handle any remaining data)
    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len)) {
        // Clean up context and throw error if finalization fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    ciphertext_len += len; // Update the total length of the ciphertext
    ciphertext.resize(ciphertext_len); // Resize the ciphertext string to the actual length

    // Prepend the IV to the ciphertext (needed for decryption)
    ciphertext = std::string(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE) + ciphertext;

    // Clean up encryption context
    EVP_CIPHER_CTX_free(ctx);

    // Return final ciphertext (IV + encrypted data)
    return ciphertext;
}

// Function to decrypt ciphertext back into plaintext using AES-256-CBC
std::string Encryption::decrypt(const std::string& ciphertext, const std::string& key) {
    // Make sure ciphertext is large enough to contain an IV
    if (ciphertext.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Invalid ciphertext");
    }

    // Create new decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        // Throw an error if context creation fails
        throw std::runtime_error("Failed to create decryption context");
    }

    // Extract the IV from the beginning of the ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    std::memcpy(iv, ciphertext.data(), AES_BLOCK_SIZE);

    // Ensure the key is the correct length (32 bytes for AES-256)
    unsigned char keyBytes[32];
    std::memset(keyBytes, 0, 32);
    std::memcpy(keyBytes, key.data(), std::min(key.size(), sizeof(keyBytes))); // Copy the key

    // Initialize decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, keyBytes, iv)) {
        // Clean up context and throw error if initialization fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    // Prepare buffer to hold the plaintext (decrypted data)
    std::string plaintext;
    plaintext.resize(ciphertext.size() - AES_BLOCK_SIZE); // Subtract IV size from ciphertext size

    int len; // Stores the length of the plaintext after each operation

    // Perform the decryption
    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
        reinterpret_cast<const unsigned char*>(ciphertext.data()) + AES_BLOCK_SIZE, ciphertext.size() - AES_BLOCK_SIZE)) {
        // Clean up context and throw error if decryption fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }

    int plaintext_len = len; // Stores length of the plaintext so far

    // Finalize decryption (handle any remaining data)
    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len)) {
        // Clean up context and throw error if finalization fails
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }

    plaintext_len += len; // Update total length of the plaintext
    plaintext.resize(plaintext_len); // Resize plaintext string to the actual length

    // Clean up decryption context
    EVP_CIPHER_CTX_free(ctx);

    // Return final plaintext (decrypted data)
    return plaintext;
}
