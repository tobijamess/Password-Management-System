#include "util.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <openssl/rand.h>
#include <stdexcept>

// Function to generate a secure password of random characters at the user chosen length
// See recovery.cpp generateRecoveryCode() for comments
std::string generateSecurePassword(int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[]{}<>?";
    std::string password(length, ' ');
    std::vector<unsigned char> randomBytes(length);
    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for password.");
    }
    for (int i = 0; i < length; ++i) {
        password[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }
    return password;
}