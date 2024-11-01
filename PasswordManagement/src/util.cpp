#include "util.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <openssl/rand.h>
#include <stdexcept>

std::string generateSecurePassword(int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[]{}<>?";
    std::string password(length, ' ');
    std::vector<unsigned char> randomBytes(length);

    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for password.");
    }

    // Fill password with random characters from charset
    for (int i = 0; i < length; ++i) {
        password[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return password;
}

// Trim leading and trailing whitespace from a string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) return str;
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

// Function to get trimmed user input from the console
std::string getTrimmedInput(const std::string& prompt) {
    std::string input;
    while (true) {
        std::cout << prompt;
        std::getline(std::cin, input);  // Get the full input
        input = trim(input);  // Trim leading and trailing spaces

        if (input.empty()) {
            std::cout << "Input cannot be empty or contain only spaces. Please try again.\n";
        }
        else {
            break;  // Input is valid
        }
    }
    return input;
}

int getIntegerInput(const std::string& prompt) {
    int input;
    while (true) {
        std::cout << prompt;
        if (std::cin >> input) {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // clear remaining input
            return input;
        }
        else {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter a number.\n";
        }
    }
}

// Generate a confirmation code with a specified length
std::string generateConfirmationCode(int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string code(length, ' ');
    std::vector<unsigned char> randomBytes(length);

    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for confirmation code.");
    }

    for (int i = 0; i < length; ++i) {
        code[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return code;
}