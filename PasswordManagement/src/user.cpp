#include "user.h"
#include "pwdStrength.h"
#include "json.hpp"
#include "encryption.h"
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

using json = nlohmann::json;

// Constructor initializes User object with username and email
User::User(const std::string& username, const std::string& email)
    : username(username), email(email) {}

// Getter for username
std::string User::getUsername() const {
    return username;
}

// Getter for email
std::string User::getEmail() const {
    return email;
}

// Hashes a given password using SHA-256 and returns it as a hexadecimal string
std::string User::hashPassword(const std::string& password) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    std::stringstream ss;
    // Convert each byte of the hash to a hex string and append it to the result
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Saves the user data to a JSON file, including the hashed password and email
bool User::saveUserData(const std::string& password) {
    hashedPassword = hashPassword(password);  // Hash and store the master password

    json userData;

    // Load existing data if it exists
    std::ifstream inFile(username + "_data.json");
    if (inFile) {
        inFile >> userData;
        inFile.close();
    }

    // Update or add the necessary fields
    userData["master_password_hash"] = hashedPassword;  // Store hashed password
    if (!userData.contains("email")) {
        userData["email"] = email;  // Preserve email if it’s already set
    }

    std::ofstream outFile(username + "_data.json");
    if (!outFile) return false;

    // Write the updated JSON data to file
    outFile << userData.dump(4);
    return true;
}

// Loads user data from a JSON file and verifies password unless in recovery mode
bool User::loadUserData(const std::string& inputPassword, bool isRecoveryMode) {
    std::ifstream file(username + "_data.json");
    if (!file) return false;

    json userData;
    file >> userData;

    // Retrieve email and hashed password from JSON data, with a check for email's existence
    if (userData.contains("email")) {
        email = userData["email"];

    }
    else {
        // Email not found in JSON data
        std::cerr << "Email not found in user data file." << std::endl;
        return false;
    }

    // Load hashed password for verification
    hashedPassword = userData["master_password_hash"];

    if (isRecoveryMode) {
        // Skip password verification in recovery mode
        return true;
    }
    else {
        // Verify that the input password matches the stored hashed password
        return verifyPassword(inputPassword);
    }
}

// Verifies that the input password matches the stored hashed password
bool User::verifyPassword(const std::string& inputPassword) const {
    return hashedPassword == hashPassword(inputPassword);
}