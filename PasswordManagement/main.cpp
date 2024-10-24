#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include "user.h"
#include "encryption.h"
#include "database.h"
#include "pwdManager.h"
#include "pwdStrength.h"
#include "smtp.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Function to initialize OpenSSL libraries
void initializeOpenSSL() {
    /* SSL_library_init();  // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();  // Load encryption algorithms
    ERR_load_crypto_strings();  // Load error strings for diagnostics */
}

// Function to generate a random secure password
std::string generateSecurePassword(int length) {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "!@#$%^&*()-_=+[]{}<>?";

    std::string password;
    password.resize(length);

    std::vector<unsigned char> randomBytes(length);
    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for password.");
    }

    // Map random bytes to character set
    for (int i = 0; i < length; ++i) {
        password[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return password;
}

// Main function
int main() {
    initializeOpenSSL();  // Initialize OpenSSL

    std::string username, masterPassword, email;
    int choice;

    while (true) {
        PasswordManager pm("");  // Initialize PasswordManager with an empty key
        bool authenticated = false;

        // Authentication loop
        while (!authenticated) {
            std::cout << "\n--- Welcome to Password Manager! ---\n";
            std::cout << "1. Create a new account\n2. Log in\n3. Exit\nChoose an option: ";
            std::cin >> choice;

            if (choice == 1) {
                // Create new account
                std::cout << "Enter desired username: ";
                std::cin >> username;
                std::cout << "Enter your email: ";
                std::cin >> email;

                if (Database::doesDatabaseExist(username)) {
                    std::cout << "This account already exists. Log in or use a different username.\n";
                    continue;
                }

                // Prompt for master password
                std::string masterPassword, masterPasswordConfirmation;
                while (true) {
                    std::cout << "Enter master password: ";
                    std::cin >> masterPassword;

                    PasswordStrength strength = evaluatePasswordStrength(masterPassword);
                    displayPasswordStrength(strength);

                    if (strength == Weak) {
                        std::cout << "Your password is too weak. Please choose a stronger one.\n";
                        continue;
                    }

                    std::cout << "Confirm master password: ";
                    std::cin >> masterPasswordConfirmation;

                    if (masterPassword == masterPasswordConfirmation) {
                        break;
                    }
                    else {
                        std::cout << "Passwords do not match. Please try again.\n";
                    }
                }

                // Register new user
                User user(username, email, 0);
                user.registerUser(masterPassword);

                // Create empty password database
                Database db(user.getUsername());
                db.createEmptyDatabase();

                pm = PasswordManager(user.getMasterKey());
                pm.loadDatabase(db.loadPasswordDatabase());

                std::cout << "Account created successfully!\n";
                authenticated = true;
            }
            else if (choice == 2) {
                // Log in
                std::cout << "Enter username: ";
                std::cin >> username;
                std::cout << "Enter master password: ";
                std::cin >> masterPassword;

                try {
                    User user(username, masterPassword, 1);
                    pm = PasswordManager(user.getMasterKey());

                    // Load the password database
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
                    std::cout << "Forgot Password? (1. Yes  2. No): ";
                    std::cin >> forgotPasswordChoice;

                    if (forgotPasswordChoice == 1) {
                        try {
                            // Load user with only username
                            User user(username, "", 2);  // You're using the constructor with the wrong flag here

                            // Add a line to load the user's email from the file
                            if (!user.loadUserEmail()) {  // This will now load the email properly
                                std::cout << "Failed to load email for the user.\n";
                            }
                            else {
                                std::string storedEmail = user.getEmail();
                                if (storedEmail.empty()) {
                                    std::cout << "No email found for this account. Please contact support.\n";
                                }
                                else {
                                    std::string recoveryCode = generateRecoveryCode();
                                    if (sendRecoveryEmail(storedEmail, recoveryCode)) {
                                        std::cout << "Recovery email sent to " << storedEmail << ".\n";
                                    }
                                    else {
                                        std::cout << "Failed to send recovery email. Please try again later.\n";
                                    }
                                }
                            }
                        }
                        catch (const std::exception& e) {
                            std::cout << "Error: " << e.what() << "\n";
                        }
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

        // Main menu
        while (true) {
            int menuChoice;
            std::cout << "\n--- Password Manager Menu ---\n";
            std::cout << "1. Add New Password\n2. Show Stored Passwords\n3. Log Out\n4. Exit\nChoose an option: ";
            std::cin >> menuChoice;

            if (menuChoice == 1) {
                // Add a new password
                std::string account, password;
                std::cout << "Enter platform or app name: ";
                std::cin >> account;

                int passwordChoice;
                std::cout << "1. Enter your password\n2. Generate a secure password\nChoose an option: ";
                std::cin >> passwordChoice;

                if (passwordChoice == 1) {
                    bool validPassword = false;

                    while (!validPassword) {
                        std::cout << "Enter your password: ";
                        std::cin >> password;

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
                    int length;
                    std::cout << "Enter desired password length: ";
                    std::cin >> length;

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
                    std::cout << "Failed to save the password to the database.\n";
                }
            }
            else if (menuChoice == 2) {
                // Show stored passwords
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