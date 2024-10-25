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

// Constructor: Initialize Database with the user-specific filename
Database::Database(const std::string& username) {
    if (username.empty()) {
        throw std::runtime_error("Username cannot be empty");
    }
    dbFilename = username + "_passwords.db";  // Set the database filename for the user
}

// Helper function to check if a file exists
bool fileExists(const std::string& filename) {
    struct STAT_STRUCT buffer;
    return (STAT_FUNCTION(filename.c_str(), &buffer) == 0);
}

// Check if the user-specific database file already exists
bool Database::doesDatabaseExist(const std::string& username) {
    std::string filename = username + "_passwords.db";  // Construct filename
    return fileExists(filename);  // Use fileExists helper function
}

// Create an empty password database for a new user
void Database::createEmptyDatabase() {
    std::string dbFilePath = dbFilename;  // Use the set filename

    // Log the file path for user awareness
    std::cout << "Attempting to create empty database at: " << dbFilePath << std::endl;

    // Open the file in write mode to create an empty file
    std::ofstream dbFile(dbFilePath, std::ios::out);
    if (!dbFile) {
        // Error handling if the file cannot be created
        std::cerr << "Error: Could not create database file at " << dbFilePath << std::endl;
        std::cerr << "Possible issues: incorrect file path, lack of write permissions, or directory issues." << std::endl;
        return;
    }

    std::cout << "Empty database file created successfully at " << dbFilePath << std::endl;
    dbFile.close();  // Close the file after creation
}

// Save the password database to the user-specific file
bool Database::savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase) {
    std::ofstream file(dbFilename);  // Open the file for writing

    if (!file.is_open()) {
        // Error handling if the file cannot be opened
        std::cerr << "Failed to open " << dbFilename << " for writing." << std::endl;
        return false;
    }

    // Write each account and its associated encrypted password to the file
    for (const auto& entry : passwordDatabase) {
        file << entry.first << " " << entry.second << std::endl;
    }

    file.close();  // Close the file after writing
    return true;
}

// Load the password database from the user-specific file
std::unordered_map<std::string, std::string> Database::loadPasswordDatabase() {
    std::unordered_map<std::string, std::string> passwordDatabase;

    // Check if the database file exists
    if (!fileExists(dbFilename)) {
        std::cerr << "Database file does not exist or is not accessible: " << dbFilename << std::endl;
        return passwordDatabase;  // Return an empty map if the file does not exist
    }

    std::ifstream file(dbFilename);  // Open the file for reading
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open " + dbFilename + " for reading");
    }

    std::string account, encryptedPassword;
    // Read each account and its encrypted password from the file
    while (file >> account >> encryptedPassword) {
        if (!account.empty() && !encryptedPassword.empty()) {
            passwordDatabase[account] = encryptedPassword;  // Add to the map if valid
        }
    }

    file.close();  // Close the file after reading
    return passwordDatabase;
}