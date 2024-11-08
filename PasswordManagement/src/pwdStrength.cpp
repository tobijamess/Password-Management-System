#include "pwdStrength.h"
#include <iostream>
#include <regex>

// Function to evaluate a password and return the strength as an enum
PasswordStrength evaluatePasswordStrength(const std::string& password) {
    // Initalize strength variable to weak by default
    PasswordStrength strength = Weak;
    // Check the length of the password, if its atleast 12 characters, set score to 1, if not set score to 0
    int lengthScore = password.length() >= 12 ? 1 : 0;
    // Regular expressions to check for if the password contains atleast one of the following character types
    std::regex uppercase("[A-Z]");         // At least one uppercase letter
    std::regex lowercase("[a-z]");         // At least one lowercase letter
    std::regex digits("[0-9]");            // At least one digit
    std::regex special("[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]");  // At least one special symbol

    // varietyScore is calculated by finding atleast one occurance of the regular expressions
    int varietyScore = std::regex_search(password, uppercase) +
        std::regex_search(password, lowercase) +
        std::regex_search(password, digits) +
        std::regex_search(password, special);

    // Calculate passwords totalScore = lengthScore + varietyScore
    int totalScore = lengthScore + varietyScore;

    // Determine password strength based on total score
    if (totalScore >= 4) {
        strength = Strong;
    }
    else if (totalScore == 3) {
        strength = Medium;
    }
    else {
        strength = Weak;
    }
    return strength;
}