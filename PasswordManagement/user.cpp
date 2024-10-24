#include "user.h"
#include "pwdStrength.h"
#include "encryption.h"
#include "pwdManager.h"
#include "database.h"
#include <openssl/sha.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <string>

// Unified constructor for user registration and login
User::User(const std::string& username, const std::string& passwordOrEmail, int mode) : username(username) {
    if (mode == 0) {
        // Registration mode: treat passwordOrEmail as email
        email = passwordOrEmail;
        saveUserEmail();  // Save the user’s email
    }
    else if (mode == 1){
        // Authentication mode: treat passwordOrEmail as password
        if (!loadMasterPassword(passwordOrEmail)) {
            throw std::runtime_error("Failed to authenticate user: " + username);
        }
    }
    else if (mode == 2) {
        // Recovery mode for email retrieval
        if (!loadUserEmail()) {
            throw std::runtime_error("Failed to load email for user: " + username);
        }
    }
}

// Get the username
std::string User::getUsername() const {
    return username;
}

// Get the email
std::string User::getEmail() const {
    return email;
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

    // Save the master password and the user's email
    saveMasterPassword();
    saveUserEmail();

    return true;
}

// Save the user's email to a file
void User::saveUserEmail() {
    std::string emailFilePath = username + "_email.txt";

    std::ofstream outFile(emailFilePath);
    if (!outFile) {
        throw std::runtime_error("Failed to save the email to file: " + emailFilePath);
    }

    outFile << email << std::endl;
    outFile.close();
}

// Save the hashed master password to a file
void User::saveMasterPassword() {
    std::string filePath = username + "_masterPwd.txt";

    std::ofstream outFile(filePath);
    if (!outFile) {
        throw std::runtime_error("Failed to save the master password to file: " + filePath);
    }

    outFile << hashedPassword << std::endl;
    outFile.close();
}

// Trim leading and trailing whitespace from a string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

// Function to get trimmed user input from the console
std::string getTrimmedInput(const std::string& prompt) {
    std::string input;
    while (true) {
        std::cout << prompt;
        std::getline(std::cin, input);  // Get the full line of input
        input = trim(input);  // Trim the input

        if (input.empty()) {
            std::cout << "Input cannot be empty or contain only spaces. Please try again.\n";
        }
        else {
            break;  // Valid input
        }
    }
    return input;
}

// Load the hashed master password from a file and compare with input password
bool User::loadMasterPassword(const std::string& inputPassword) {
    std::string filePath = username + "_masterPwd.txt";

    // Load the saved hashed password
    std::ifstream inFile(filePath);
    if (!inFile) {
        std::cerr << "Error: Could not open file " << filePath << " for reading." << std::endl;
        return false;
    }

    std::getline(inFile, hashedPassword);
    inFile.close();

    // Hash the input password and compare it to the stored hashed password
    std::string hashedInputPassword = hashPassword(inputPassword);
    return (hashedPassword == hashedInputPassword);
}

// Load the user's email from the file
bool User::loadUserEmail() {
    std::string emailFilePath = username + "_email.txt";

    std::ifstream emailFile(emailFilePath);
    if (!emailFile) {
        std::cerr << "Error: Could not open file " << emailFilePath << " for reading." << std::endl;
        return false;
    }

    std::getline(emailFile, email);
    email = trim(email);
    emailFile.close();

    if (email.empty()) {
        std::cerr << "Error: Email for user " << username << " is empty after loading from file." << std::endl;
        return false;
    }

    return true;
}

bool User::updateMasterPassword(const std::string& newPassword) {
    PasswordStrength strength = evaluatePasswordStrength(newPassword);

    if (strength == Weak) {
        std::cerr << "Weak password. Please choose a stronger password." << std::endl;
        return false; // Fail if the password is weak
    }

    // Hash the new password
    hashedPassword = hashPassword(newPassword);

    // Save the new master password to the file
    try {
        saveMasterPassword();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to save the updated password: " << e.what() << std::endl;
        return false;
    }
}

// Return the hashed master key
std::string User::getMasterKey() const {
    return hashedPassword;
}