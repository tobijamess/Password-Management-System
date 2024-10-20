#include <iostream>
#include "user.h"
#include "database.h"
#include "pwdManager.h"
#include "encryption.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Function to initialize OpenSSL libraries
void initializeOpenSSL() {
    SSL_library_init();  // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();  // Load encryption algorithms
    ERR_load_crypto_strings();  // Load error strings for diagnostics
}

int main() {
    initializeOpenSSL();  // Initialize OpenSSL

    std::string username, masterPassword;  // Store user's username and master password
    int choice;  // Store the user's choice for menu options

    while (true) {
        // Outer loop: Manage user authentication
        PasswordManager pm("");  // Initialize PasswordManager with an empty key
        bool authenticated = false;  // Track if the user is authenticated

        while (!authenticated) {
            // Authentication loop
            std::cout << "\n--- Welcome to Password Manager! ---\n1. Create a new account\n2. Log in\n3. Exit\nChoose an option: ";
            std::cin >> choice;

            if (choice == 1) {
                // User selects account creation
                std::cout << "Enter username: ";
                std::cin >> username;

                // Check if the account already exists
                if (Database::doesDatabaseExist(username)) {
                    std::cout << "This account already exists. Log in or use a different username.\n";
                    continue;
                }

                // Prompt for master password
                std::cout << "Enter master password: ";
                std::cin >> masterPassword;

                // Register new user
                User user(username);
                user.registerUser(masterPassword);

                // Create an empty database for the new user
                Database db(user.getUsername());
                db.createEmptyDatabase();

                // Initialize PasswordManager with the user's master key
                pm = PasswordManager(user.getMasterKey());
                pm.loadDatabase(db.loadPasswordDatabase());

                std::cout << "Account created successfully!\n";
                authenticated = true;  // User is now authenticated
            }
            else if (choice == 2) {
                // User selects login
                std::cout << "Enter username: ";
                std::cin >> username;
                std::cout << "Enter master password: ";
                std::cin >> masterPassword;

                try {
                    // Load user data and authenticate with the provided password
                    User user(username, masterPassword);
                    pm = PasswordManager(user.getMasterKey());

                    // Load the password database
                    Database db(user.getUsername());
                    pm.loadDatabase(db.loadPasswordDatabase());

                    std::cout << "Login successful!\n";
                    authenticated = true;  // User is now authenticated
                }
                catch (const std::exception& e) {
                    std::cout << e.what() << std::endl;
                    continue;  // Retry login if authentication fails
                }
            }
            else if (choice == 3) {
                // Exit the program
                std::cout << "Exiting...\n";
                return 0;
            }
            else {
                std::cout << "Invalid option!\n";  // Handle invalid input
            }
        }

        // Main menu loop: After successful authentication
        int menuChoice;
        while (true) {
            std::cout << "\n--- Password Manager Menu ---\n";
            std::cout << "1. Add New Password\n2. Show Stored Passwords\n3. Log Out\n4. Exit\nChoose an option: ";
            std::cin >> menuChoice;

            if (menuChoice == 1) {
                // Option to add a new password
                std::cout << "\n--- Adding Passwords ---\n";
                std::string account, password;
                std::cout << "Enter platform or app name: ";
                std::cin >> account;
                std::cout << "Enter your password: ";
                std::cin >> password;

                // Add password to the manager
                pm.addPassword(account, password);

                // Save the updated password database
                Database db(username);
                if (db.savePasswordDatabase(pm.getPasswordDatabase())) {
                    std::cout << "Password added successfully!\n";
                }
                else {
                    std::cout << "Failed to save the password to the database.\n";
                }
            }
            else if (menuChoice == 2) {
                // Option to show stored passwords
                std::cout << "\n--- Viewing Stored Passwords ---\n";
                for (const auto& entry : pm.getPasswordDatabase()) {
                    std::cout << "Account: " << entry.first << ", Password: " << pm.getPassword(entry.first) << std::endl;
                }
            }
            else if (menuChoice == 3) {
                // Log out: Reset authentication
                std::cout << "Logging out...\n";
                break;
            }
            else if (menuChoice == 4) {
                // Exit the program
                std::cout << "Exiting...\n";
                return 0;
            }
            else {
                std::cout << "Invalid option!\n";  // Handle invalid input
            }
        }
    }

    return 0;
}