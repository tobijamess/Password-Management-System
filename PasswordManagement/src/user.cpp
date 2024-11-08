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

// Define constructor for User class that takes username and email parameters (using a constructor because each User object needs to have username and email values upon creation)
User::User(const std::string& username, const std::string& email) : username(username), email(email) {}

// Getter for username stored in User object
std::string User::getUsername() const {
    return username;
}
// Getter for email stored in User object
std::string User::getEmail() const {
    return email;
}

// Hashes a given password using SHA-256 and returns it as a hexadecimal string
std::string User::hashPassword(const std::string& password) const {
    // Declar a hash array with a size of SHA256_DIGEST_LENGTH which is 32 bytes to hold the binary result of the hashing
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // Openssl function to convert password string to unsigned char* which is the type of string needed by SHA256 (reinterpret_cast<const unsigned char*<(password.c_str())
    // password.size() specifies length of password in bytes, hash is the variable the SHA256 function stores the result in, which will be stored in the hash array
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    // Declares a stringstream object to construct the hexadecimal string representation of the hash
    std::stringstream ss;
    // Loops through each byte of the hash array (32 times because SHA256_DIGEST_LENGTH is 32 bytes large)
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        // ss << hex sets stringstream to output hexadecimal values, setw(2) makes sure each byte is represented by two chars
        // setfill('0') specifies that a '0' should be used to fill any extra space left by setw, static_cast<int>(hash[i]) converts each byte to an int so it can be printed as hexadecimal
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    // Convert ss object contents into a string to be returned
    return ss.str();
}

// Saves the user data to a JSON file, including the hashed password and email
bool User::saveUserData(const std::string& password) {
    // Call hashPassword() function and passs in the users password to get a hash and store it in hashedPassword
    hashedPassword = hashPassword(password);
    // Declare json object to hold all a users data in one .json file
    json userData;
    // inFile opens an input file stream to read the user specific .json file
    std::ifstream inFile(username + "_data.json");
    // Check if it opened successfully
    if (inFile) {
        // If the file exists, read contents into the userData json object to make sure existing data is preserved
        inFile >> userData;
        inFile.close();
    }
    // Set or update the master_password_hash field in the userData json object with the hashed password
    userData["master_password_hash"] = hashedPassword;
    // Check if an email field exists in userData, if not then add it
    if (!userData.contains("email")) {
        userData["email"] = email;
    }
    // outFile opens an output file stream to now write data to the user specific .json file, if it doesn't exist, create one
    std::ofstream outFile(username + "_data.json");
    // If file doesn't open return false
    if (!outFile) return false;

    // Write the userData json object to outFile, (4) is the space indentation to make it easier to read
    outFile << userData.dump(4);
    return true;
}

// Function to load user data from .json and verifies the password unless the account is in recovery mode
bool User::loadUserData(const std::string& inputPassword, bool isRecoveryMode) {
    // Opens .json that stores based on username
    std::ifstream file(username + "_data.json");
    // Return false if file cant be opened
    if (!file) return false;
    // Create json object 'userData' and read file contents into it
    json userData;
    file >> userData;
    // Chcek if userData object has an email field, if it does, assign email value to userData's email attribute
    if (userData.contains("email")) {
        email = userData["email"];
    }
    else {
        // Email not found in JSON data
        std::cerr << "Email not found in user data file." << std::endl;
        return false;
    }
    // Read hashed master password from userData object so it can be used for verification during login
    hashedPassword = userData["master_password_hash"];
    // Check if the account is in recovery mode
    if (isRecoveryMode) {
        // If account is in recovery, skip the password verification
        return true;
    }
    else {
        // If account is not in recovery, call verifyPassword()
        return verifyPassword(inputPassword);
    }
}
// Function to verify that the password input during login has the same hash as the one in storage (to verify login)
// Every time a user tries to login, the password they input is hashed and compared with the hash that is stored in their user specific .json file
bool User::verifyPassword(const std::string& inputPassword) const {
    return hashedPassword == hashPassword(inputPassword);
}