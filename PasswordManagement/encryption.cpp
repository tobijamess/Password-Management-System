#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>

std::string Encryption::encrypt(const std::string& plaintext, const std::string& key) {
	std::string ciphertext = "encrypted_" + plaintext;
	return ciphertext;
}

std::string Encryption::decrypt(const std::string& ciphertext, const std::string& key) {
	std::string plaintext = ciphertext.substr(10);
	return plaintext;
}