#ifndef PWDMANAGER_H
#define PWDMANAGER_H

#include <string>
#include <unordered_map>

class PasswordManager {
public:
    // Constructor initializes the master key for encryption/decryption
    PasswordManager(const std::string& masterKey);

    // Encrypts and stores a password for a given account
    void addPassword(const std::string& account, const std::string& password);

    // Decrypts and retrieves the password for a given account
    std::string getPassword(const std::string& account) const;

    // Returns the entire password database
    std::unordered_map<std::string, std::string> getPasswordDatabase() const;

    // Loads a password database into the manager
    void loadDatabase(const std::unordered_map<std::string, std::string>& db);

private:
    std::string masterKey;  // Master key used for encryption and decryption
    std::unordered_map<std::string, std::string> passwordDatabase;  // Stores encrypted passwords
};

#endif // PWDMANAGER_H