#include "user.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>

// Constructor initializes the User object with a username and attempts to load the master password
User::User(const std::string& username) : username(username) {
    if (!loadMasterPassword()) {
        throw std::runtime_error("Failed to load master password for user: " + username);
    }
}

// Hashes the given password using SHA-256 and returns the resulting hexadecimal string
std::string User::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash); // Compute the SHA-256 hash

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i]; // Convert hash to hex string
    }
    return ss.str();
}

// Registers a new user by hashing the given password and saving it
bool User::registerUser(const std::string& password) {
    hashedPassword = hashPassword(password); // Hash the password
    saveMasterPassword(); // Save the hashed password to a file
    return true;
}

// Verifies a password by comparing its hashed value with the stored hashed password
bool User::login(const std::string& password) {
    std::string hashedInput = hashPassword(password); // Hash the input password
    return hashedInput == hashedPassword; // Compare with the stored hashed password
}

// Saves the hashed master password to a file
void User::saveMasterPassword() {
    std::ofstream outFile("masterPwd.txt");
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to open masterPwd.txt for writing"); // Error if file can't be opened
    }
    outFile << hashedPassword; // Write the hashed password to the file
    outFile.close();
}

// Loads the hashed master password from a file
bool User::loadMasterPassword() {
    std::ifstream inFile("masterPwd.txt");
    if (inFile.is_open()) {
        std::getline(inFile, hashedPassword); // Read the hashed password from the file
        inFile.close();
        return true;
    }
    return false; // Return false if file can't be opened or read
}

// Returns the hashed master password
std::string User::getMasterKey() const {
    return hashedPassword;
}
