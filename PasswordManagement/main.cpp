#include <iostream>
#include "user.h"
#include "database.h"
#include "pwdManager.h"
#include "encryption.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Function to initialize OpenSSL
void initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_library_init();
}

// Function to generate random salt
std::vector<unsigned char> generateSalt() {
    std::vector<unsigned char> salt(16);
    if (!RAND_bytes(salt.data(), salt.size())) {
        throw std::runtime_error("Failed to generate salt");
    }
    return salt;
}

int main() {
    // Initialize OpenSSL
    initializeOpenSSL();

    std::string username, masterPassword;
    int choice;

    PasswordManager pm("");  // Initialize with empty master key temporarily

    while (true) {
        // Display menu options for account creation or login
        std::cout << "\n1. Create a new account" << std::endl;
        std::cout << "2. Log in" << std::endl;
        std::cout << "Choose an option: ";
        std::cin >> choice;

        if (choice == 1) {
            // Account creation process
            std::cout << "Enter username: ";
            std::cin >> username;

            // Check if database already exists, loop back to menu if it does
            if (Database::doesDatabaseExist(username)) {
                std::cout << "An account with this username already exists. Please log in or choose a different username." << std::endl;
                continue;  // Loop back to the account creation/login menu
            }

            std::cout << "Enter master password: ";
            std::cin >> masterPassword;

            User user(username);
            user.registerUser(masterPassword);

            // Create the user's password database
            Database db(user.getUsername());
            db.createEmptyDatabase();

            // Initialize PasswordManager with the user's master key and load the (empty) database
            pm = PasswordManager(user.getMasterKey());
            pm.loadDatabase(db.loadPasswordDatabase());

            std::cout << "Master Key during registration: " << user.getMasterKey() << std::endl;

            std::cout << "Account created successfully!" << std::endl;
            break;  // Exit the loop and proceed to the password management menu
        } 
        else if (choice == 2) {
            // User login process
            std::cout << "Enter username: ";
            std::cin >> username;

            std::cout << "Enter master password: ";
            std::cin >> masterPassword;

            try {
                // Authenticate the user and retrieve the master key
                User user(username, masterPassword);
                std::string masterKey = user.getMasterKey();  // Get the hashed master key

                std::cout << "Login successful!" << std::endl;

                // Initialize PasswordManager with the user's master key and load the database
                Database db(user.getUsername());
                pm = PasswordManager(masterKey);
                pm.loadDatabase(db.loadPasswordDatabase());

                std::cout << "Master Key after login: " << masterKey << std::endl;

                if (pm.getPasswordDatabase().empty()) {
                    std::cout << "No passwords stored yet." << std::endl;
                }
                break;  // Exit the loop and proceed to the password management menu
            }
            catch (const std::exception& e) {
                std::cout << e.what() << std::endl;
                continue;  // Stay in the menu loop if login fails
            }
        }
        else {
            std::cout << "Invalid option selected!" << std::endl;
            continue;  // Stay in the menu loop for invalid input
        }
    }

    // Menu loop for managing passwords
    int menuChoice;
    while (true) {
        std::cout << "\n--- Password Manager Menu ---\n";
        std::cout << "1. Add New Password\n";
        std::cout << "2. Show Stored Passwords\n";
        std::cout << "3. Exit\n";
        std::cout << "Choose an option: ";
        std::cin >> menuChoice;

        if (menuChoice == 1) {
            std::string account, password;
            std::cout << "Enter account name (e.g., Gmail, Facebook): ";
            std::cin >> account;
            std::cout << "Enter password: ";
            std::cin >> password;

            // Add new password to database file
            pm.addPassword(account, password);

            // Save the updated password database to the file
            Database db(username);
            bool saveSuccess = db.savePasswordDatabase(pm.getPasswordDatabase());

            if (saveSuccess) {
                std::cout << "Password added successfully!" << std::endl;
            }
            else {
                std::cout << "Failed to save the password database." << std::endl;
            }
        }
        // View stored passwords
        else if (menuChoice == 2) {
            try {
                auto passwordDatabase = pm.getPasswordDatabase();
                std::cout << "\n--- Stored Passwords ---\n";
                for (const auto& entry : passwordDatabase) {
                    std::cout << "Account: " << entry.first << ", Password: " << pm.getPassword(entry.first) << std::endl;
                }
            }
            catch (const std::runtime_error& e) {
                std::cout << "Error: " << e.what() << std::endl;
            }
        }
        else if (menuChoice == 3) {
            std::cout << "Exiting...\n";
            break;
        }
        else {
            std::cout << "Invalid option selected!" << std::endl;
        }
    }

    return 0;
}