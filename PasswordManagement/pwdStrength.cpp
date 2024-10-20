#include "pwdStrength.h"
#include <iostream>
#include <regex>

// Function to evaluate password strength
PasswordStrength evaluatePasswordStrength(const std::string& password) {
    PasswordStrength strength = Weak;

    // Check length
    int lengthScore = password.length() >= 12 ? 1 : 0;

    // Check for uppercase, lowercase, digits, and symbols
    std::regex uppercase("[A-Z]");
    std::regex lowercase("[a-z]");
    std::regex digits("[0-9]");
    std::regex special("[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]");

    int varietyScore = std::regex_search(password, uppercase) +
        std::regex_search(password, lowercase) +
        std::regex_search(password, digits) +
        std::regex_search(password, special);

    int totalScore = lengthScore + varietyScore;

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

// Function to display password strength feedback
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