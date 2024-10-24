#include "database.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

#ifdef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#define STAT_STRUCT _stat64  // Use _stat64 for Windows
#define STAT_FUNCTION _stat64
#endif

// Constructor: Initialize with a specific filename
Database::Database(const std::string& username) {

    if (username.empty()) {
        throw std::runtime_error("Username cannot be empty");
    }
    dbFilename = username + "_passwords.db";
}

// Helper function to check if a file exists
bool fileExists(const std::string& filename) {
    struct STAT_STRUCT buffer;
    return (STAT_FUNCTION(filename.c_str(), &buffer) == 0);
}

// Checks if the user-specific database file already exists
bool Database::doesDatabaseExist(const std::string& username) {
    std::string filename = username + "_passwords.db";
    return fileExists(filename);
}

// Creates an empty password database for a new user
void Database::createEmptyDatabase() {
    std::string dbFilePath = dbFilename;  // Use the user-specific filename

    // Log the file path
    std::cout << "Attempting to create empty database at: " << dbFilePath << std::endl;

    // Open the file in write mode to create an empty file if it doesn't exist
    std::ofstream dbFile(dbFilePath, std::ios::out);

    if (!dbFile) {
        std::cerr << "Error: Could not create database file at " << dbFilePath << std::endl;
        std::cerr << "Possible issues: incorrect file path, lack of write permissions, or directory issues." << std::endl;
        return;
    }

    // Log success
    std::cout << "Empty database file created successfully at " << dbFilePath << std::endl;

    dbFile.close();
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