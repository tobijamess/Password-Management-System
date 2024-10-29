#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <limits>
#include "user.h"
#include "database.h"
#include "pwdManager.h"
#include "pwdStrength.h"
#include "util.h"
#include "recovery.h"
#include <openssl/rand.h>

#define NOMINMAX

// Function to generate a secure random password
std::string generateSecurePassword(int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[]{}<>?";
    std::string password(length, ' ');
    std::vector<unsigned char> randomBytes(length);

    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for password.");
    }

    for (int i = 0; i < length; ++i) {
        password[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return password;
}

int main() {
    std::string username, masterPassword;
    int choice;

    while (true) {
        PasswordManager pm("");
        bool authenticated = false;

        while (!authenticated) {
            std::cout << "\n--- Welcome to Password Manager! ---\n";
            std::cout << "1. Create a new account\n2. Log in\n3. Exit\n ";
            choice = getIntegerInput("Choose an option: ");

            if (choice == 1) {
                username = getTrimmedInput("Enter desired username: ");
                std::string email = getTrimmedInput("Enter your email: ");

                if (Database::fileExists(username)) {
                    std::cout << "This account already exists.\n";
                    continue;
                }

                std::string masterPassword, masterPasswordConfirmation;
                while (true) {
                    masterPassword = getTrimmedInput("Enter master password: ");
                    if (evaluatePasswordStrength(masterPassword) == Weak) {
                        std::cout << "Weak password. Please choose a stronger one.\n";
                        continue;
                    }
                    masterPasswordConfirmation = getTrimmedInput("Confirm master password: ");
                    if (masterPassword == masterPasswordConfirmation) break;
                    std::cout << "Passwords do not match. Try again.\n";
                }

                User user(username, email);
                if (!user.saveUserData(masterPassword)) {
                    std::cout << "Failed to save user data.\n";
                    continue;
                }

                std::cout << "Account created successfully!\n";
                authenticated = true;
            }
            else if (choice == 2) {
                username = getTrimmedInput("Enter username: ");
                masterPassword = getTrimmedInput("Enter master password: ");

                User user(username, masterPassword);
                if (!user.loadUserData(masterPassword, false)) {
                    std::cout << "Authentication failed.\n";
                    accountRecovery(username);
                }

                Database db(username);
                pm.loadDatabase(db.loadPasswordDatabase());
                std::cout << "Login successful!\n";
                authenticated = true;
            }
            else if (choice == 3) {
                std::cout << "Exiting...\n";
                return 0;
            }
            else {
                std::cout << "Invalid option!\n";
            }
        }

        while (true) {
            int menuChoice;
            std::cout << "\n--- Password Manager Menu ---\n";
            std::cout << "1. Add New Password\n2. Show Stored Passwords\n3. Log Out\n4. Exit\n";
            menuChoice = getIntegerInput("Choose an option: ");

            if (menuChoice == 1) {
                std::string account = getTrimmedInput("Enter platform or app name: ");
                std::string password;
                int passwordChoice;

                std::cout << "1. Enter your password\n2. Generate a secure password\n";
                passwordChoice = getIntegerInput("Choose an option: ");

                if (passwordChoice == 1) {
                    while (true) {
                        password = getTrimmedInput("Enter your password: ");
                        if (evaluatePasswordStrength(password) != Weak) break;
                        std::cout << "Password too weak. Choose another.\n";
                    }
                }
                else if (passwordChoice == 2) {
                    int length;
                    std::cout << "Enter password length:\n";
                    length = getIntegerInput("Length: ");
                    password = generateSecurePassword(length);
                    std::cout << "Generated password: " << password << std::endl;
                }
                else {
                    std::cout << "Invalid option!\n";
                    continue;
                }

                pm.addPassword(account, password);
                Database db(username);

                if (db.savePasswordDatabase(pm.getPasswordDatabase())) {
                    std::cout << "Password added successfully!\n";
                }
                else {
                    std::cout << "Failed to save password.\n";
                }
            }
            else if (menuChoice == 2) {
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