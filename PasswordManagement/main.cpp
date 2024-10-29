#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <limits>
#include "user.h"
#include "encryption.h"
#include "database.h"
#include "pwdManager.h"
#include "pwdStrength.h"
#include "recovery.h"
#include "smtp.h"
#include "util.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NOMINMAX  // Prevent issues with the Windows min/max macros

// Function to generate a secure random password
std::string generateSecurePassword(int length) {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "!@#$%^&*()-_=+[]{}<>?";

    std::string password(length, ' ');
    std::vector<unsigned char> randomBytes(length);

    // Generate random bytes for secure password
    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for password.");
    }

    // Map random bytes to characters from the charset
    for (int i = 0; i < length; ++i) {
        password[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return password;
}

int main() {

    std::string username, masterPassword, email;
    int choice;

    // Main loop for the password manager
    while (true) {
        PasswordManager pm("");  // Initialize with an empty key
        bool authenticated = false;

        // User authentication loop
        while (!authenticated) {
            std::cout << "\n--- Welcome to Password Manager! ---\n";
            std::cout << "1. Create a new account\n2. Log in\n3. Exit\n ";
            choice = getIntegerInput("Choose an option: ");
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');  // Clear input buffer

            if (choice == 1) {
                // Account creation process
                username = getTrimmedInput("Enter desired username: ");
                email = getTrimmedInput("Enter your email: ");

                if (Database::doesDatabaseExist(username)) {
                    std::cout << "This account already exists. Log in or use a different username.\n";
                    continue;
                }

                // Prompt for a strong master password
                std::string masterPassword, masterPasswordConfirmation;
                while (true) {
                    masterPassword = getTrimmedInput("Enter master password: ");
                    PasswordStrength strength = evaluatePasswordStrength(masterPassword);
                    displayPasswordStrength(strength);

                    if (strength == Weak) {
                        std::cout << "Your password is too weak. Please choose a stronger one.\n";
                        continue;
                    }

                    masterPasswordConfirmation = getTrimmedInput("Confirm master password: ");
                    if (masterPassword == masterPasswordConfirmation) break;
                    else std::cout << "Passwords do not match. Please try again.\n";
                }

                // Register new user and create an empty password database
                User user(username, email, 0);
                user.registerUser(masterPassword);

                // Send confirmation code to the user's email
                if (!user.sendConfirmationCode()) {
                    std::cout << "Failed to send confirmation email. Please try again later.\n";
                    continue;
                }

                std::cout << "Confirmation email sent. Please check your inbox to verify your account.\n";

                // Loop for entering confirmation code
                while (true) {
                    std::string enteredCode = getTrimmedInput("Enter the confirmation code sent to your email: ");

                    if (user.verifyConfirmationCode(enteredCode)) {
                        std::cout << "Account confirmed successfully! You can now log in.\n";
                        break; // Break the loop on successful confirmation
                    }
                    else {
                        std::cout << "Invalid confirmation code. Please try again.\n";
                    }
                }

                // Create empty password database and proceed
                Database db(user.getUsername());
                db.createEmptyDatabase();

                pm = PasswordManager(user.getMasterKey());
                pm.loadDatabase(db.loadPasswordDatabase());

                authenticated = true;
            }
            else if (choice == 2) {
                // Login process
                username = getTrimmedInput("Enter username: ");
                masterPassword = getTrimmedInput("Enter master password: ");

                try {
                    User user(username, masterPassword, 1);
                    pm = PasswordManager(user.getMasterKey());

                    Database db(user.getUsername());
                    if (!Database::doesDatabaseExist(username)) {
                        std::cout << "Password database file missing. Creating a new one...\n";
                        db.createEmptyDatabase();
                    }

                    pm.loadDatabase(db.loadPasswordDatabase());
                    std::cout << "Login successful!\n";
                    authenticated = true;

                }
                catch (const std::exception& e) {
                    std::cout << "Authentication failed: " << e.what() << "\n";

                    int forgotPasswordChoice;
                    std::cout << "Forgot Password?\n1. Yes\n2. No, try again\n";
                    forgotPasswordChoice = getIntegerInput("Choose an option: ");
                    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

                    if (forgotPasswordChoice == 1) {
                        accountRecovery(username);
                    }
                }

            }
            else if (choice == 3) {
                std::cout << "Exiting...\n";
                return 0;

            }
            else {
                std::cout << "Invalid option!\n";
            }
        }

        // Main menu after authentication
        while (true) {
            int menuChoice;
            std::cout << "\n--- Password Manager Menu ---\n";
            std::cout << "1. Add New Password\n2. Show Stored Passwords\n3. Log Out\n4. Exit\n";
            menuChoice = getIntegerInput("Choose an option: ");
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

            if (menuChoice == 1) {
                // Add a new password
                std::string account, password;
                account = getTrimmedInput("Enter platform or app name: ");

                int passwordChoice;
                std::cout << "1. Enter your password\n2. Generate a secure password\n";
                passwordChoice = getIntegerInput("Choose an option: ");
                std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

                if (passwordChoice == 1) {
                    // Enter user-defined password and validate its strength
                    bool validPassword = false;
                    while (!validPassword) {
                        password = getTrimmedInput("Enter your password: ");
                        PasswordStrength strength = evaluatePasswordStrength(password);
                        displayPasswordStrength(strength);

                        if (strength == Weak) {
                            std::cout << "Your password is too weak. Please choose a stronger one.\n";
                        }
                        else {
                            validPassword = true;
                        }
                    }
                }
                else if (passwordChoice == 2) {
                    // Generate a secure password
                    int length;
                    std::cout << "Enter desired password character length: ";
                    length = getIntegerInput("Length:");
                    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

                    password = generateSecurePassword(length);
                    std::cout << "Generated password: " << password << std::endl;
                }
                else {
                    std::cout << "Invalid option!\n";
                    continue;
                }

                // Save the password to the database
                pm.addPassword(account, password);
                Database db(username);

                if (db.savePasswordDatabase(pm.getPasswordDatabase())) {
                    std::cout << "Password added successfully!\n";
                }
                else {
                    std::cout << "Failed to save the password to the database.\n";
                }

            }
            else if (menuChoice == 2) {
                // Display stored passwords
                std::cout << "\n--- Viewing Stored Passwords ---\n";
                for (const auto& entry : pm.getPasswordDatabase()) {
                    std::cout << "Account: " << entry.first << ", Password: " << pm.getPassword(entry.first) << std::endl;
                }

            }
            else if (menuChoice == 3) {
                std::cout << "Logging out...\n";
                break;

            }
            else if (menuChoice == 4) {
                std::cout << "Exiting...\n";
                return 0;

            }
            else {
                std::cout << "Invalid option!\n";
            }
        }
    }

    return 0;
}