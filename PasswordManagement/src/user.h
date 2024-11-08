#ifndef USER_H
#define USER_H
#include <string>

class User {
private:
    std::string username;
    std::string email;
public:
    User() = default; // Default constructor for cases needing an uninitialized User
    User(const std::string& username, const std::string& email);
    std::string getUsername() const;
    std::string getEmail() const;
    bool saveUserData(const std::string& password);
    bool loadUserData(const std::string& inputPassword, bool isRecoveryMode = false);
    bool verifyPassword(const std::string& inputPassword) const;
private:
    std::string hashedPassword;
    std::string hashPassword(const std::string& password) const;
};
#endif