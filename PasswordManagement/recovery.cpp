#include "recovery.h"
#include "user.h"
#include "pwdStrength.h"
#include "smtp.h" // For email functions
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <stdexcept>

// Function to generate a recovery code
std::string generateRecoveryCode() {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string code(6, ' ');
    std::vector<unsigned char> randomBytes(6);

    if (RAND_bytes(randomBytes.data(), 6) != 1) {
        throw std::runtime_error("Error generating random bytes for recovery code.");
    }

    for (int i = 0; i < 6; ++i) {
        code[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return code;
}

// Function to handle password recovery for a user
void accountRecovery(const std::string& username) {
    try {
        // Load user data from JSON
        User user(username, "");
        if (!user.loadUserData("", true)) {  // Attempt to load data without verifying password
            std::cout << "Failed to load user data.\n";
            return;
        }

        std::string storedEmail = user.email;
        if (storedEmail.empty()) {
            std::cout << "No email found for this account. Please contact support.\n";
            return;
        }

        // Generate and send recovery code
        std::string recoveryCode = generateRecoveryCode();
        if (!sendRecoveryEmail(storedEmail, recoveryCode)) {
            std::cout << "Failed to send recovery email. Please try again later.\n";
            return;
        }
        std::cout << "Recovery email sent to " << storedEmail << ".\n";

        // Code entry and password reset loop
        while (true) {
            std::string enteredCode = getTrimmedInput("Enter the recovery code: ");

            if (enteredCode == "exit") {
                std::cout << "Returning to the main menu...\n"; // Remove this for UI
                return;
            }

            if (enteredCode == recoveryCode) {
                std::cout << "Recovery code verified.\n";

                // Password reset loop
                while (true) {
                    std::string newPassword = getTrimmedInput("Enter new master password: ");
                    std::string confirmPassword = getTrimmedInput("Confirm new master password: ");

                    if (newPassword != confirmPassword) {
                        std::cout << "Passwords do not match. Please try again.\n";
                        continue;
                    }

                    // Update password in the user data and re-encrypt database
                    if (!user.saveUserData(newPassword)) {
                        std::cout << "Failed to update password.\n";
                        return;
                    }

                    std::cout << "Password reset successfully!\n";
                    break;
                }
                break;
            }
            else {
                std::cout << "Invalid recovery code. Please try again.\n";
            }
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
    }
}