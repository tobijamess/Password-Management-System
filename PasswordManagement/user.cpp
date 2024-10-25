#include "user.h"
#include "pwdStrength.h"
#include "encryption.h"
#include "pwdManager.h"
#include "database.h"
#include "smtp.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <string>

// Trim leading and trailing whitespace from a string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) return str;
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

// Function to get trimmed user input from the console
std::string getTrimmedInput(const std::string& prompt) {
    std::string input;
    while (true) {
        std::cout << prompt;
        std::getline(std::cin, input);  // Get the full input
        input = trim(input);  // Trim leading and trailing spaces

        if (input.empty()) {
            std::cout << "Input cannot be empty or contain only spaces. Please try again.\n";
        }
        else {
            break;  // Input is valid
        }
    }
    return input;
}

// Unified constructor for different user operations: registration, login, or recovery
User::User(const std::string& username, const std::string& passwordOrEmail, int mode) : username(username) {
    if (mode == 0) {
        // Registration mode: passwordOrEmail is treated as an email
        email = passwordOrEmail;
        saveUserEmail();  // Save the user’s email during registration
    }
    else if (mode == 1) {
        // Authentication mode: passwordOrEmail is treated as a password
        if (!loadMasterPassword(passwordOrEmail)) {
            throw std::runtime_error("Failed to authenticate user: " + username);
        }
    }
    else if (mode == 2) {
        // Recovery mode: load user's email for password recovery
        if (!loadUserEmail()) {
            throw std::runtime_error("Failed to load email for user: " + username);
        }
    }
}

// Return the username
std::string User::getUsername() const {
    return username;
}

// Return the email
std::string User::getEmail() const {
    return email;
}

// Return the hashed master password
std::string User::getMasterKey() const {
    return hashedPassword;
}

// Save the hashed master password to a file
void User::saveMasterPassword() {
    std::string filePath = username + "_masterPwd.txt";
    std::ofstream outFile(filePath);
    if (!outFile) {
        throw std::runtime_error("Failed to save the master password to file: " + filePath);
    }
    outFile << hashedPassword << std::endl;
}

// Hash the password using SHA-256
std::string User::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    // Convert the hash to a hex string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Load the hashed master password from a file and compare it to the input password
bool User::loadMasterPassword(const std::string& inputPassword) {
    std::string filePath = username + "_masterPwd.txt";
    std::ifstream inFile(filePath);
    if (!inFile) {
        std::cerr << "Error: Could not open file " << filePath << " for reading.\n";
        return false;
    }

    std::getline(inFile, hashedPassword);
    inFile.close();

    // Hash the input password and compare with stored hash
    std::string hashedInputPassword = hashPassword(inputPassword);
    return (hashedPassword == hashedInputPassword);
}

// Update the user's master password after validating its strength and saving it
bool User::updateMasterPassword(const std::string& newPassword) {
    PasswordStrength strength = evaluatePasswordStrength(newPassword);
    if (strength == Weak) {
        std::cerr << "Weak password. Please choose a stronger password.\n";
        return false;  // Fail if the password is weak
    }

    // Hash and save the new password
    hashedPassword = hashPassword(newPassword);
    try {
        saveMasterPassword();  // Save the new hashed password
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to save the updated password: " << e.what() << std::endl;
        return false;
    }
}

// Register a new user: validate password strength, hash it, and save credentials
bool User::registerUser(const std::string& password) {
    // Check password strength
    PasswordStrength strength = evaluatePasswordStrength(password);
    if (strength == Weak) {
        throw std::runtime_error("Weak password. Please choose a stronger password.");
    }

    // Hash the password and save it
    hashedPassword = hashPassword(password);
    saveMasterPassword();  // Save the hashed password
    saveUserEmail();       // Save the user email

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
}

// Load the user's email from the file
bool User::loadUserEmail() {
    std::string emailFilePath = username + "_email.txt";
    std::ifstream emailFile(emailFilePath);
    if (!emailFile) {
        std::cerr << "Error: Could not open file " << emailFilePath << " for reading.\n";
        return false;
    }

    std::getline(emailFile, email);
    email = trim(email);  // Trim any excess whitespace
    emailFile.close();

    if (email.empty()) {
        std::cerr << "Error: Email for user " << username << " is empty after loading.\n";
        return false;
    }

    return true;
}

std::string generateConfirmationCode(int length = 6) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string code(length, ' ');
    std::vector<unsigned char> randomBytes(length);

    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for confirmation code.");
    }

    for (int i = 0; i < length; ++i) {
        code[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return code; // Return the generated confirmation code
}

bool User::sendConfirmationCode() {
    confirmationCode = generateConfirmationCode(); // Generate a new confirmation code
    return sendRecoveryEmail(email, confirmationCode); // Reusing sendRecoveryEmail for sending
}

bool User::verifyConfirmationCode(const std::string& code) {
    if (code == confirmationCode) {
        isAccountLocked = false; // Unlock the account
        return true; // Verification successful
    }
    return false; // Verification failed
}

void User::lockAccount() {
    isAccountLocked = true; // Lock the account
}

void User::unlockAccount() {
    isAccountLocked = false; // Unlock the account
}