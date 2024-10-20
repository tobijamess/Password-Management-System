#include "database.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <sys/stat.h>

// Constructor: Initialize with a specific filename
Database::Database(const std::string& username) {

    if (username.empty()) {
        throw std::runtime_error("Username cannot be empty");
    }
    dbFilename = username + "_passwords.db";
}

// Helper function to check if a file exists
bool fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

// Checks if the user-specific database file already exists
bool Database::doesDatabaseExist(const std::string& username) {
    std::string filename = username + "_passwords.db";
    return fileExists(filename);
}

// Creates an empty password database for a new user
void Database::createEmptyDatabase() {
    std::ofstream file(dbFilename);  // Create the file
    if (!file.is_open()) {
        throw std::runtime_error("Failed to create " + dbFilename);
    }
    file.close();
}

// Saves the password database to a user-specific file
bool Database::savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase) {
    std::ofstream file(dbFilename);  // Open file for writing

    if (!file.is_open()) {
        std::cerr << "Failed to open " << dbFilename << " for writing." << std::endl;
        return false;
    }

    // Write each account and its Base64-encoded encrypted password to the file
    for (const auto& entry : passwordDatabase) {
        file << entry.first << " " << entry.second << std::endl;
    }

    file.close();
    return true;
}

// Loads the password database from the user-specific file
std::unordered_map<std::string, std::string> Database::loadPasswordDatabase() {
    std::unordered_map<std::string, std::string> passwordDatabase;

    // Check if the file exists first
    if (!fileExists(dbFilename)) {
        std::cerr << "Database file does not exist or is not accessible: " << dbFilename << std::endl;
        return passwordDatabase;  // Return an empty database if file doesn't exist
    }

    std::ifstream file(dbFilename);  // Open user-specific database file

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open " + dbFilename + " for reading");
    }

    std::string account, encryptedPassword;
    while (file >> account >> encryptedPassword) {
        // Ensure that both the account and encrypted password are being read correctly
        if (!account.empty() && !encryptedPassword.empty()) {
            passwordDatabase[account] = encryptedPassword;
            /* std::cout << "Loaded: Account = " << account << ", Encrypted Password = " << encryptedPassword << std::endl; */ 
        }
    }

    file.close();
    return passwordDatabase;
}