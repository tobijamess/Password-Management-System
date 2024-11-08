#include "database.h"
#include "user.h"
#include "UI.h"
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

// Database constructor thats called when a Database object is created, dbFilename member variable allocates a storage path for each users database file
Database::Database(const std::string& username) : dbFilename(username + "_data.json") {}

// Checks if a file exists by checking its status in the filesystem
bool Database::fileExists(const std::string& filename) {
    // Declare stat structure called buffer which holds info about the file, if it exists
    struct stat buffer;
    // stat fills the buffer structure with info about filename, if the file exists, stat returns true (or 0)
    return (stat(filename.c_str(), &buffer) == 0);
}

// Creates an empty .json database file for the user to store passwords and track recovery status
void Database::createEmptyDatabase() {
    // Opens or creates a file with the name dbFilename to be written to (ofstream auto makes a file if it doesnt exist)
    std::ofstream dbFile(dbFilename);
    // Check if file was successfully opened
    if (dbFile) {
        // Initialize a json object called emptyDb with an empty json array for storing passwords, and a recovery flag
        json emptyDb = {
            {"passwords", json::array()},
            {"recovery_in_progress", false}
        };
        // Write emptyDb's data to the file (dbFilename)
        dbFile << emptyDb.dump(4);
    }
}

// Function to save and update a user's password database in their file, it takes an unordered_map reference
// Because the password database contains a service or account name and a password for that account (key-value)
bool Database::savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase) {
    // Open users database file for reading
    std::ifstream file(dbFilename);
    // Declare json object userData to hold current contents of the .json file
    json userData;
    // Load existing user data if the file is accessible
    if (file) file >> userData;
    // Check if userData has a "passwords" key, then check if "passwords" is an object (because its meant to store the key-value pairs)
    // If it doesn't exist or isn't an object, userData[] = json::object() creates an empty json object so it can now store password entries
    if (!userData.contains("passwords") || !userData["passwords"].is_object()) {
        userData["passwords"] = json::object();
    }
    // Iterate over each key-value pair in passwordDatabase (it->first is account name, it->second is the accounts corresponding password)
    for (auto it = passwordDatabase.begin(); it != passwordDatabase.end(); ++it) {
        // For every entry, update userData with account name and its' password, if theres an existing account password pair, overwrite the value with this new one
        userData["passwords"][it->first] = it->second;
    }
    // Open the database file (dbFilename) for writing
    std::ofstream outFile(dbFilename);
    // File cant be opened, return false
    if (!outFile) return false;
    // Write the updated JSON data to file (4 space indents again)
    outFile << userData.dump(4);
    return true;
}

// Function to load password database from .json file into an unordered_map
std::unordered_map<std::string, std::string> Database::loadPasswordDatabase() {
    // Create an empty unordered_map to hold the password database where each entry a key-value (account name and corresponding password)
    std::unordered_map<std::string, std::string> passwordDatabase;
    // Opens dbFilename for reading
    std::ifstream file(dbFilename);
    // Check if file was opened successfully
    if (file) {
        // Create json object 'userData' and read file contents into it
        json userData;
        file >> userData;
        // Iterate over each entry in the "passwords" object within userData
        for (auto& item : userData["passwords"].items()) {
            // Extract account name (key) from each entry
            std::string key = item.key();
            // Extract password (value) that corresponds with account name for each entry
            std::string value = item.value();
            // Insert the key-value pair into the passwordDatabase map
            passwordDatabase[key] = value;
        }
    }
    // Return map containing all the now-loaded key-value pairs
    return passwordDatabase;
}

// Sets the account's recovery status, and optionally a recovery code, in the json database
bool Database::setRecoveryStatus(const std::string& username, bool inRecovery, const std::string& recoveryCode) {
    std::ifstream file(dbFilename);
    if (!file) return false;
    // Refer to above functions
    json userData;
    file >> userData;
    // Close input file to prevent conflicts when opening it for output later on
    file.close();

    // Updates or creates "recovery_in_progress" key in userData and sets it to 'inRecovery' (which indicates if there is an active recovery process)
    userData["recovery_in_progress"] = inRecovery;
    // If inRecovery is true, store the recoveryCode in its field in userData
    if (inRecovery) {
        userData["recovery_code"] = recoveryCode;
    }
    // If not, remove the recovery_code key from userData
    else {
        userData.erase("recovery_code");
    }
    // Refer to above functions
    std::ofstream outFile(dbFilename);
    if (!outFile) return false;
    // Write the updated json data to file
    outFile << userData.dump(4);
    return true;
}

// Gets the recovery status and code from the .json file if recovery is in progress
bool Database::getRecoveryStatus(const std::string& username, std::string& recoveryCode) {
    // Refer to above functions
    std::ifstream file(dbFilename);
    if (!file) return false;
    // Refer to above functions
    json userData;
    file >> userData;
    // Retrieve the value of "recovery_in_progress" from userData, if that key isnt found, default to false
    bool inRecovery = userData.value("recovery_in_progress", false);
    // If inRecovery is true, get the recovery code that is stored under "recovery_code", if not found, default to empty string
    if (inRecovery) {
        recoveryCode = userData.value("recovery_code", "");
        // Return true if recovery is active and the code was retrieved
        return true;
    }
    // If recovery isnt active, return false
    return false;
}
// Function to validate the recovery code that the user inputs during recovery
bool Database::validateRecoveryCode(const std::string& username, std::string& inputCode) {
    // Refer to above functions
    std::ifstream file(dbFilename);
    if (!file) return false;
    // Refer to above functions
    json userData;
    file >> userData;
    // Retrieve recovery status
    bool inRecovery = userData.value("recovery_in_progress", false);
    // Retrieve recovery code
    std::string storedRecoveryCode = userData.value("recovery_code", "");

    // Check inRecovery is true, and check if the inputted recovery code matches the stored one, return true if they do
    return inRecovery && (inputCode == storedRecoveryCode);
}
// Clears ONLY passwords from the .json database file (for when recovery is finished and they need to store a new hashed master password)
bool Database::clearPasswords() {
    // Refer to above functions
    std::ifstream file(dbFilename);
    if (!file) return false;
    // Refer to above functions
    json userData;
    file >> userData;
    file.close();
    // Clear the "passwords" key by setting it to an empty json array (only clear passwords so email field is preserved through a master password reset)
    userData["passwords"] = json::array();
    // Refer to above functions
    std::ofstream outFile(dbFilename);
    if (!outFile) return false;
    // Refer to above functions
    outFile << userData.dump(4);
    return true;
}