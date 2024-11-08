#include "pwdManager.h"
#include "encryption.h"
#include "json.hpp"
#include <stdexcept>

using json = nlohmann::json;

// Constructor that initalizes an instance of the PasswordManager class with the given master key (hashed master password)
PasswordManager::PasswordManager(const std::string& key) : masterKey(key) {}

// Adds an account and its associated password to the database after encrypting the password
void PasswordManager::addPassword(const std::string& account, const std::string& password) {
    // Pass the newly added password to the password encryption function along with the masterKey to encrypt it and store result in encryptedPassword string
    std::string encryptedPassword = encryptPassword(password, masterKey);
    // Store the encryptedPassword as the value alongside its key (account) in the passwordDatabase map
    passwordDatabase[account] = encryptedPassword;
}
// Retrieves the password for a given account and decrypt it and then return it
std::string PasswordManager::getPassword(const std::string& account) const {
    // Look up the account in the passwordDatabase map, find() returns an iterator (it) to the account with its matching key or passwordDatabase.end() if key doesn't exist
    auto it = passwordDatabase.find(account);
    // Check if account was found in the map
    if (it != passwordDatabase.end()) {
        // If the account exists, decrypt and return the password
        return decryptPassword(it->second, masterKey);
    }
    // If the account is not found, throw an exception
    throw std::runtime_error("Account not found");
}
// Returns the entire password database as an unordered map of account-password pairs (string, string)
std::unordered_map<std::string, std::string> PasswordManager::getPasswordDatabase() const {
    return passwordDatabase;
}
// Pass a reference to a map that holds encrypted account-password pairs (db) and then point passwordDatabase map to db so passwordDatabase is 'updated' with the contents of db
void PasswordManager::loadDatabase(const std::unordered_map<std::string, std::string>& db) {
    passwordDatabase = db;
}