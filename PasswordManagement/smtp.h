#include <string>

// Generates a recovery code of the specified length
std::string generateRecoveryCode(int length = 6);

// Sends a recovery email with the specified recovery code to the given email address
bool sendRecoveryEmail(const std::string& email, const std::string& recoveryCode);