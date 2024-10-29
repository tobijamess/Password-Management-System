#include "user.h"
#include "pwdStrength.h"
#include "json.hpp"
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

User::User(const std::string& username, const std::string& email) : username(username), email(email) {}

std::string User::hashPassword(const std::string& password) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool User::saveUserData(const std::string& password) {
    hashedPassword = hashPassword(password);

    json userData;
    userData["master_password_hash"] = hashedPassword;
    userData["email"] = email;

    std::ofstream file(username + "_data.json");
    if (!file) return false;

    file << userData.dump(4);
    return true;
}

bool User::loadUserData(const std::string& inputPassword, bool isRecoveryMode) {
    std::ifstream file(username + "_data.json");
    if (!file) return false;

    json userData;
    file >> userData;

    email = userData["email"];
    hashedPassword = userData["master_password_hash"];

    if (isRecoveryMode) {
        // Skip password verification in recovery mode
        return true;
    }
    else {
        // Verify the password only if not in recovery mode
        return verifyPassword(inputPassword);
    }
}
bool User::verifyPassword(const std::string& inputPassword) const {
    return hashedPassword == hashPassword(inputPassword);
}