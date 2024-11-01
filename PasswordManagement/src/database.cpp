#include "database.h"
#include "user.h"
#include "UI.h"
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

// Constructor initializes database file path based on the username
Database::Database(const std::string& username)
    : dbFilename(username + "_data.json") {}

// Checks if a file exists by checking its status in the filesystem
bool Database::fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

// Creates an empty JSON database file if it does not already exist
void Database::createEmptyDatabase() {
    std::ofstream dbFile(dbFilename);
    if (dbFile) {
        json emptyDb = {
            {"passwords", json::array()},         // Empty array to store passwords
            {"recovery_in_progress", false}       // Flag to indicate if recovery mode is active
        };
        dbFile << emptyDb.dump(4);               // Write formatted JSON to file
    }
}

// Saves the password database to the JSON file, overwriting existing data
bool Database::savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase) {
    std::ifstream file(dbFilename);
    json userData;

    // Load existing user data if the file is accessible
    if (file) file >> userData;

    // Check if "passwords" key exists and is an object; if not, create it
    if (!userData.contains("passwords") || !userData["passwords"].is_object()) {
        userData["passwords"] = json::object();
    }

    // Update the JSON with new entries without overwriting
    for (auto it = passwordDatabase.begin(); it != passwordDatabase.end(); ++it) {
        userData["passwords"][it->first] = it->second;
    }

    std::ofstream outFile(dbFilename);
    if (!outFile) return false;

    // Write the updated JSON data to file
    outFile << userData.dump(4); // Pretty-formatted JSON
    return true;
}

// Loads the password database from the JSON file into a C++ map
std::unordered_map<std::string, std::string> Database::loadPasswordDatabase() {
    std::unordered_map<std::string, std::string> passwordDatabase;
    std::ifstream file(dbFilename);

    if (file) {
        json userData;
        file >> userData;

        // Convert JSON passwords into a C++ map for easy access
        for (auto& item : userData["passwords"].items()) {
            std::string key = item.key();
            std::string value = item.value();
            passwordDatabase[key] = value;
        }
    }
    return passwordDatabase;
}

// Sets the account's recovery status, and optionally a recovery code, in the database
bool Database::setRecoveryStatus(const std::string& username, bool inRecovery, const std::string& recoveryCode) {
    std::ifstream file(dbFilename);
    if (!file) return false;

    json userData;
    file >> userData;
    file.close();

    // Update recovery status and optionally store the recovery code
    userData["recovery_in_progress"] = inRecovery;
    if (inRecovery) {
        userData["recovery_code"] = recoveryCode;
    }
    else {
        userData.erase("recovery_code"); // Remove code if recovery is not active
    }

    std::ofstream outFile(dbFilename);
    if (!outFile) return false;

    // Write the updated JSON data to file
    outFile << userData.dump(4);
    return true;
}

// Gets the recovery status and code from the JSON file if recovery is in progress
bool Database::getRecoveryStatus(const std::string& username, std::string& recoveryCode) {
    std::ifstream file(dbFilename);
    if (!file) return false;

    json userData;
    file >> userData;

    // Retrieve recovery status and code (default to false if not defined)
    bool inRecovery = userData.value("recovery_in_progress", false);

    if (inRecovery) {
        recoveryCode = userData.value("recovery_code", ""); // Get recovery code if available
        return true;
    }
    return false;
}

bool Database::validateRecoveryCode(const std::string& username, std::string& inputCode) {
    std::ifstream file(dbFilename);
    if (!file) return false;

    json userData;
    file >> userData;

    // Ensure recovery is in progress and retrieve the stored recovery code
    bool inRecovery = userData.value("recovery_in_progress", false);
    std::string storedRecoveryCode = userData.value("recovery_code", "");

    // Return true if recovery is active and the input code matches the stored code
    return inRecovery && (inputCode == storedRecoveryCode);
}

// Clears all passwords from the database but keeps other account info like email
bool Database::clearPasswords() {
    std::ifstream file(dbFilename);
    if (!file) return false;

    json userData;
    file >> userData;
    file.close();

    // Clear passwords array in JSON data but retain other fields
    userData["passwords"] = json::array();

    std::ofstream outFile(dbFilename);
    if (!outFile) return false;

    // Write the updated JSON data to file
    outFile << userData.dump(4);
    return true;
}