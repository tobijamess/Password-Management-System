#ifndef PASSWORD_STRENGTH_H
#define PASSWORD_STRENGTH_H

#include <string>

// Enum for password strength levels
enum PasswordStrength {
    Weak,
    Medium,
    Strong
};

// Function declarations
PasswordStrength evaluatePasswordStrength(const std::string& password);

void displayPasswordStrength(PasswordStrength strength);

#endif // PASSWORD_STRENGTH_H