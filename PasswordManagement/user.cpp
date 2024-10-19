#include "user.h"
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>

// Constructor initializes the User object with a username and attempts to load the master password
User::User(const std::string& username, const std::string& inputPassword) : username(username) {
    if (!loadMasterPassword(inputPassword)) {
        throw std::runtime_error("Failed to authenticate user: " + username);
    }
}

// Constructor for account creation (username only)
User::User(const std::string& username) : username(username) {

}

// Returns the username
std::string User::getUsername() const {
    return username;
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
    std::string filename = username + "_masterPwd.txt"; //Uses username to create unique master password file
    std::ofstream outFile(filename);
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to open " + filename + " masterPwd.txt for writing"); // Error if file can't be opened
    }
    outFile << hashedPassword; // Write the hashed password to the file
    outFile.close();
}

// Loads the hashed master password from a file
bool User::loadMasterPassword(const std::string& inputPassword) {
    std::string filename = username + "_masterPwd.txt";
    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        throw std::runtime_error("Failed to open " + filename + " masterPwd.txt for reading");
    }

    std::string storedHashedPassword;
    inFile >> storedHashedPassword; // Read hashed password from file
    inFile.close();

    std::string inputHashedPassword = hashPassword(inputPassword);

    // Ensure the stored hashed password is set correctly in the object after login
    if (storedHashedPassword == inputHashedPassword) {
        hashedPassword = storedHashedPassword;  // Store the hashed password in the User object
        return true;
    }
    else {
        return false;
    }
}

// Returns the hashed master password
std::string User::getMasterKey() const {
    return hashedPassword;
}
