#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <vector>
#include <stdexcept>

// Helper function to convert binary data into Base64 string
std::string toBase64(const std::vector<unsigned char>& binaryData) {
    BIO* bio = BIO_new(BIO_s_mem());  // Create memory BIO
    BIO* b64 = BIO_new(BIO_f_base64());  // Create Base64 filter BIO
    bio = BIO_push(b64, bio);  // Push Base64 BIO onto the memory BIO

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // Set flag to disable newline in Base64 output
    BIO_write(bio, binaryData.data(), binaryData.size());  // Write binary data
    BIO_flush(bio);  // Ensure all data is written

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);  // Get pointer to the Base64-encoded string
    std::string base64Data(bufferPtr->data, bufferPtr->length);  // Copy the Base64 data into a string

    BIO_free_all(bio);  // Clean up BIO objects
    return base64Data;  // Return the Base64-encoded string
}

// Helper function to convert Base64 string back into binary data
std::vector<unsigned char> fromBase64(const std::string& base64Data) {
    BIO* bio = BIO_new_mem_buf(base64Data.data(), base64Data.size());  // Create a memory buffer BIO
    BIO* b64 = BIO_new(BIO_f_base64());  // Create Base64 filter BIO
    bio = BIO_push(b64, bio);  // Push Base64 BIO onto the memory buffer BIO

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // Disable newline in Base64 input
    std::vector<unsigned char> binaryData(base64Data.size());  // Prepare a buffer for the binary data
    int decodedLength = BIO_read(bio, binaryData.data(), binaryData.size());  // Read and decode Base64

    BIO_free_all(bio);  // Clean up BIO objects
    binaryData.resize(decodedLength);  // Resize buffer to actual decoded length
    return binaryData;  // Return decoded binary data
}

// Encrypts the plaintext password using AES-256-CBC and returns the encrypted Base64 string
std::string encryptPassword(const std::string& plaintext, const std::string& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create encryption context
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);  // Initialize buffer for IV (initialization vector)
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);  // Prepare buffer for ciphertext
    int len, ciphertext_len;

    if (!RAND_bytes(iv.data(), iv.size())) throw std::runtime_error("Failed to generate IV");  // Generate random IV

    // Initialize encryption operation using AES-256-CBC
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv.data());
    // Perform encryption
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);  // Finalize encryption
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);  // Clean up encryption context

    // Combine IV and ciphertext and return as a Base64 string
    std::vector<unsigned char> result(iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    return toBase64(result);
}

// Decrypts the Base64-encoded ciphertext using AES-256-CBC and returns the plaintext password
std::string decryptPassword(const std::string& base64Ciphertext, const std::string& key) {
    std::vector<unsigned char> ciphertext = fromBase64(base64Ciphertext);  // Decode Base64 string to binary data
    if (ciphertext.size() < EVP_MAX_IV_LENGTH) throw std::runtime_error("Ciphertext too short");  // Check length

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create decryption context
    std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + EVP_MAX_IV_LENGTH);  // Extract IV
    std::vector<unsigned char> plaintext(ciphertext.size());  // Buffer for decrypted text

    // Initialize decryption operation
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv.data());

    int len, plaintext_len;
    // Perform decryption
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + EVP_MAX_IV_LENGTH, ciphertext.size() - EVP_MAX_IV_LENGTH);
    plaintext_len = len;

    // Finalize decryption
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) throw std::runtime_error("Decryption failed");  // Check for errors during finalization

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);  // Clean up decryption context

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);  // Return decrypted plaintext as string
}
