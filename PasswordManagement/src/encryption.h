#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

// Function to encrypt a password
std::string encryptPassword(const std::string& plaintext, const std::string& key);

// Function to decrypt a password
std::string decryptPassword(const std::string& ciphertext, const std::string& key);

#endif // ENCRYPTION_H