#include "database.h"
#include "user.h"
#include "pwdStrength.h"
#include "smtp.h" // For email functions
#include "recovery.h"
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

// Function to handle account recovery with persistent recovery status
void accountRecovery(const std::string& username) {
    try {
        // Load user data without password verification
        User user(username, "");
        if (!user.loadUserData("", true)) {
            std::cout << "Failed to load user data.\n";
            return;
        }

        // Retrieve the email associated with the account
        std::string storedEmail = user.getEmail();
        if (storedEmail.empty()) {
            std::cout << "No email found for this account. Please contact support.\n";
            return;
        }

        std::cout << "Account Recovery Loaded Email TEST: " << storedEmail << std::endl;

        Database db(username);
        std::string recoveryCode;

        // Check if recovery is already in progress
        if (!db.getRecoveryStatus(username, recoveryCode)) {
            // Generate and store a new recovery code if recovery is not already set
            recoveryCode = generateRecoveryCode();
            db.setRecoveryStatus(username, true, recoveryCode);

            // Send the recovery code via email
            if (!sendRecoveryEmail(storedEmail, recoveryCode)) {
                std::cout << "Failed to send recovery email. Please try again later.\n";
                return;
            }
            std::cout << "Recovery email sent to " << storedEmail << ".\n";
        }

        // Recovery code entry and verification loop
        while (true) {
            std::string enteredCode = getTrimmedInput("Enter the recovery code: ");

            if (enteredCode == "exit") {
                std::cout << "Returning to the main menu...\n";
                return;
            }

            if (enteredCode == recoveryCode) {
                std::cout << "Recovery code verified.\n";

                // Reset the password and clear the recovery status in the database
                db.setRecoveryStatus(username, false);  // Clear the recovery status immediately after verification

                // Password reset loop
                while (true) {
                    std::string newPassword = getTrimmedInput("Enter new master password: ");
                    std::string confirmPassword = getTrimmedInput("Confirm new master password: ");

                    if (newPassword != confirmPassword) {
                        std::cout << "Passwords do not match. Please try again.\n";
                        continue;
                    }

                    // Update password in user data
                    if (user.saveUserData(newPassword)) {
                        // Clear stored passwords after updating the password
                        if (db.clearPasswords()) {
                            std::cout << "Password reset successfully and old passwords cleared!\n";
                        }
                        else {
                            std::cout << "Password reset, but failed to clear old passwords.\n";
                        }
                    }
                    else {
                        std::cout << "Failed to update password.\n";
                        return;
                    }

                    std::cout << "Password reset successfully!\n";

                    // Clear old passwords after successful reset
                    if (!db.clearPasswords()) {
                        std::cout << "Failed to clear old passwords.\n";
                        return;
                    }

                    break;
                }

                // Break out of the outer loop to prevent re-triggering recovery
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