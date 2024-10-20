#include "user.h"
#include "pwdStrength.h"
#include <openssl/sha.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>

// Constructor for user authentication
User::User(const std::string& username, const std::string& inputPassword) : username(username) {
    if (!loadMasterPassword(inputPassword)) {
        throw std::runtime_error("Failed to authenticate user: " + username);
    }
}

// Constructor for user registration
User::User(const std::string& username) : username(username) {}

// Get the username
std::string User::getUsername() const {
    return username;
}

// Hash the password using SHA-256
std::string User::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Register a new user by hashing the password and saving it
bool User::registerUser(const std::string& password) {
    PasswordStrength strength = evaluatePasswordStrength(password);

    if (strength == Weak) {
        throw std::runtime_error("Weak password. Please choose a stronger password.");
    }

    hashedPassword = hashPassword(password);
    saveMasterPassword();
    return true;
}

// Save the hashed master password to a file
void User::saveMasterPassword() {
    std::ofstream outFile(username + "_masterPwd.txt");
    if (!outFile) throw std::runtime_error("Failed to open file for writing");
    outFile << hashedPassword;
}

// Load and verify the master password from a file
bool User::loadMasterPassword(const std::string& inputPassword) {
    std::ifstream inFile(username + "_masterPwd.txt");
    if (!inFile) throw std::runtime_error("Failed to open file for reading");

    std::string storedHashedPassword;
    inFile >> storedHashedPassword;

    if (storedHashedPassword == hashPassword(inputPassword)) {
        hashedPassword = storedHashedPassword;
        return true;
    }
    return false;
}

// Return the hashed master key
std::string User::getMasterKey() const {
    return hashedPassword;
}
