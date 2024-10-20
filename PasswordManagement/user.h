#ifndef USER_H
#define USER_H

#include <string>

class User {
public:
    // Constructor initializes the User object with a username and loads the master password
    User(const std::string& username, const std::string& inputPassword);

    // Overload for account creation without a password
    User(const std::string& username);

    // Registers a new user by hashing the given password and saving it
    bool registerUser(const std::string& password);

    // Returns the hashed master password
    std::string getMasterKey() const;

    // Returns the username
    std::string getUsername() const;

private:
    std::string username;        // Stores the username for the user
    std::string hashedPassword;  // Stores the hashed master password

    // Hashes the given password using SHA-256
    std::string hashPassword(const std::string& password);

    // Loads the hashed master password from a file
    bool loadMasterPassword(const std::string& inputPassword);

    // Saves the hashed master password to a file
    void saveMasterPassword();
};

#endif // USER_H
