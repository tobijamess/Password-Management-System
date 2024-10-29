#ifndef USER_H
#define USER_H
#include <string>

class User {
public:

    // Unified constructor for both registration and login
    User(const std::string& username, const std::string& email);

    bool verifyPassword(const std::string& inputPassword) const;

    bool saveUserData(const std::string& password);
    bool loadUserData(const std::string& inputPassword, bool isRecoveryMode);

    std::string username;        // Stores the username for the user
    std::string email;           // Stores the users email

private:

    std::string hashedPassword;  // Stores the hashed master password
    std::string hashPassword(const std::string& password) const;     // Hashes the given password using SHA-256
    std::string confirmationCode;                              // Store the confirmation code
    
};

#endif // USER_H