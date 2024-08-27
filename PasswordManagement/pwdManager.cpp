#include "pwdManager.h"
#include "encryption.h"
#include <stdexcept>
#include <unordered_map>

// Constructor initializes the PasswordManager with the given master key
PasswordManager::PasswordManager(const std::string& masterKey)
    : masterKey(masterKey) {}

// Adds a new password to the database, encrypting it first
void PasswordManager::addPassword(const std::string& account, const std::string& password) {
    std::string encryptedPassword = encryptPassword(password, masterKey);
    passwordDatabase[account] = encryptedPassword;
}

// Retrieves the password for a given account, decrypting it
std::string PasswordManager::getPassword(const std::string& account) const {
    auto it = passwordDatabase.find(account);
    if (it != passwordDatabase.end()) {
        return decryptPassword(it->second, masterKey);
    }
    else {
        throw std::runtime_error("Account not found.");
    }
}

// Returns the entire password database
std::unordered_map<std::string, std::string> PasswordManager::getPasswordDatabase() const {
    if (passwordDatabase.empty()) {
        throw std::runtime_error("No passwords stored.");
    }
    return passwordDatabase;
}

// Loads a password database into the manager
void PasswordManager::loadDatabase(const std::unordered_map<std::string, std::string>& db) {
    passwordDatabase = db;
}
