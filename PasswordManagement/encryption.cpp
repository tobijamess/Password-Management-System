#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <string>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Helper function to convert binary data to Base64
std::string toBase64(const std::vector<unsigned char>& binaryData) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines in output
    BIO_write(bio, binaryData.data(), binaryData.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string base64Data(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return base64Data;
}

// Helper function to convert Base64 string back to binary
std::vector<unsigned char> fromBase64(const std::string& base64Data) {
    BIO* bio = BIO_new_mem_buf(base64Data.data(), base64Data.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines in input
    std::vector<unsigned char> binaryData(base64Data.size());
    int decodedLength = BIO_read(bio, binaryData.data(), binaryData.size());

    BIO_free_all(bio);

    binaryData.resize(decodedLength);  // Resize vector to actual decoded length
    return binaryData;
}

// Encrypts the given plaintext using AES-256-CBC and the provided key
std::string encryptPassword(const std::string& plaintext, const std::string& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);  // IV length depends on the cipher
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len;

    // Generate a random IV
    if (!RAND_bytes(iv.data(), iv.size())) {
        throw std::runtime_error("Failed to generate IV");
    }

    // Initialize encryption operation with the IV
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), iv.data());

    // Perform encryption
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Prepend IV to the ciphertext
    std::vector<unsigned char> result(iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    // Convert binary data (IV + ciphertext) to Base64 for storage
    return toBase64(result);
}

// Decrypts the given ciphertext using AES-256-CBC and the provided key
std::string decryptPassword(const std::string& base64Ciphertext, const std::string& key) {
    // Convert Base64 string back to binary data
    std::vector<unsigned char> ciphertext = fromBase64(base64Ciphertext);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    std::vector<unsigned char> plaintext(ciphertext.size());  // Buffer for decrypted text
    int len, plaintext_len;

    // Check if the ciphertext is long enough to contain both IV and encrypted data
    if (ciphertext.size() < iv.size()) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ciphertext too short to contain IV");
    }

    // Extract the IV from the beginning of the ciphertext
    std::copy(ciphertext.begin(), ciphertext.begin() + iv.size(), iv.begin());

    // Initialize decryption operation with the IV
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), iv.data());

    // Perform decryption
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data() + iv.size()), ciphertext.size() - iv.size());
    plaintext_len = len;

    // Finalize decryption
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) {  // Check for decryption failure
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Return the decrypted plaintext
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}