#include "pwdStrength.h"
#include <iostream>
#include <regex>

// Function to evaluate the strength of a given password
PasswordStrength evaluatePasswordStrength(const std::string& password) {
    PasswordStrength strength = Weak;  // Default to weak

    // Check if password length is at least 12 characters
    int lengthScore = password.length() >= 12 ? 1 : 0;

    // Regular expressions to check for variety of characters in the password
    std::regex uppercase("[A-Z]");         // At least one uppercase letter
    std::regex lowercase("[a-z]");         // At least one lowercase letter
    std::regex digits("[0-9]");            // At least one digit
    std::regex special("[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]");  // At least one special symbol

    // Check if password contains these character types
    int varietyScore = std::regex_search(password, uppercase) +
        std::regex_search(password, lowercase) +
        std::regex_search(password, digits) +
        std::regex_search(password, special);

    // Total score = length score + variety score
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

// Function to display password strength feedback to the user
void displayPasswordStrength(PasswordStrength strength) {
    switch (strength) {
    case Weak:
        std::cout << "Password Strength: Weak\n";
        break;
    case Medium:
        std::cout << "Password Strength: Medium\n";
        break;
    case Strong:
        std::cout << "Password Strength: Strong\n";
        break;
    }
}