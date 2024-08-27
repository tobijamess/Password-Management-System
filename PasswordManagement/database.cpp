#include "database.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

// Saves the password database to a file
void Database::savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase) {
    std::ofstream file("passwords.db"); // Open file for writing
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open passwords.db for writing"); // Error if file can't be opened
    }

    // Write each account and its encrypted password to the file
    for (const auto& entry : passwordDatabase) {
        file << entry.first << " " << entry.second << std::endl;
    }

    file.close(); // Close the file after writing
}

// Loads the password database from a file
std::unordered_map<std::string, std::string> Database::loadPasswordDatabase() {
    std::unordered_map<std::string, std::string> passwordDatabase; // Create an empty map for passwords
    std::ifstream file("passwords.db"); // Open file for reading

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open passwords.db for reading"); // Error if file can't be opened
    }

    std::string account, encryptedPassword;
    // Read each line from the file and add it to the map
    while (file >> account >> encryptedPassword) {
        passwordDatabase[account] = encryptedPassword;
    }

    file.close(); // Close the file after reading
    return passwordDatabase; // Return the loaded password database
}
