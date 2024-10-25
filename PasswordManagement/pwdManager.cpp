#include "pwdManager.h"
#include "encryption.h"
#include <stdexcept>

// Constructor that initializes the PasswordManager with the master encryption key
PasswordManager::PasswordManager(const std::string& key) : masterKey(key) {}

// Adds an account and its associated password to the database after encrypting the password
void PasswordManager::addPassword(const std::string& account, const std::string& password) {
    // Encrypt the password using the master key
    std::string encryptedPassword = encryptPassword(password, masterKey);
    // Store the encrypted password in the database with the account as the key
    passwordDatabase[account] = encryptedPassword;
}

// Retrieves the password for a given account after decrypting it
std::string PasswordManager::getPassword(const std::string& account) const {
    // Look up the account in the password database
    auto it = passwordDatabase.find(account);
    if (it != passwordDatabase.end()) {
        // If the account exists, decrypt and return the password
        return decryptPassword(it->second, masterKey);
    }
    // If the account is not found, throw an exception
    throw std::runtime_error("Account not found");
}

// Returns the entire password database as an unordered map of account-password pairs
std::unordered_map<std::string, std::string> PasswordManager::getPasswordDatabase() const {
    return passwordDatabase;
}

// Loads an existing password database into the current password manager
void PasswordManager::loadDatabase(const std::unordered_map<std::string, std::string>& db) {
    passwordDatabase = db;  // Replace the current database with the provided one
}