#include <string>

// Sends a recovery email with the specified recovery code to the given email address
bool sendRecoveryEmail(const std::string& email, const std::string& recoveryCode);