#ifndef USER_H
#define USER_H

#include <string>

class User {
public:

    // Unified constructor for both registration and login
    User(const std::string& username, const std::string& passwordOrEmail, int mode);

    // Registers a new user by hashing the given password and saving it
    bool registerUser(const std::string& password);

    std::string getMasterKey() const;  // Returns the hashed master password
    std::string getUsername() const;   // Returns the username
    std::string getEmail() const;      // Returns the email
    bool loadUserEmail();              // Loads users email

private:
    std::string username;        // Stores the username for the user
    std::string hashedPassword;  // Stores the hashed master password
    std::string email;           // Stores the users email

    std::string hashPassword(const std::string& password);     // Hashes the given password using SHA-256
    bool loadMasterPassword(const std::string& inputPassword); // Loads the hashed master password from a file
    void saveMasterPassword();                                 // Saves the hashed master password
    void saveUserEmail();                                      // Saves the users email
    
};

#endif // USER_H