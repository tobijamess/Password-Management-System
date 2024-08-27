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
    OpenSSL_add_all_algorithms();  // Load all encryption and hashing algorithms
    ERR_load_crypto_strings();     // Load error strings for cryptographic operations
    SSL_library_init();            // Initialize SSL library
}

// Function to generate a random salt
std::vector<unsigned char> generateSalt() {
    std::vector<unsigned char> salt(16); // 128-bit salt
    if (!RAND_bytes(salt.data(), salt.size())) {
        throw std::runtime_error("Failed to generate salt"); // Error if salt generation fails
    }
    return salt;
}

int main() {
    // Initialize OpenSSL
    initializeOpenSSL();

    std::string username, masterPassword;
    int choice;

    // Display menu options for account creation or login
    std::cout << "1. Create a new account" << std::endl;
    std::cout << "2. Log in" << std::endl;
    std::cout << "Choose an option: ";
    std::cin >> choice;

    User user(""); // Initialize a User object
    if (choice == 1) {
        // Account creation process
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter master password: ";
        std::cin >> masterPassword;

        user = User(username); // Create a User object with the given username
        user.registerUser(masterPassword); // Register the user with the master password

        std::cout << "Account created successfully!" << std::endl;
    }
    else if (choice == 2) {
        // User login process
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter master password: ";
        std::cin >> masterPassword;

        user = User(username); // Create a User object with the given username
        if (!user.login(masterPassword)) {
            std::cout << "Invalid password!" << std::endl;
            return 1; // Exit if login fails
        }

        std::cout << "Login successful!" << std::endl;
    }
    else {
        std::cout << "Invalid option selected!" << std::endl;
        return 1; // Exit if an invalid option is selected
    }

    PasswordManager pm(user.getMasterKey()); // Initialize PasswordManager with the user's master key

    // Load existing password data from the database
    Database db;
    pm.loadDatabase(db.loadPasswordDatabase());

    // Menu loop for managing passwords
    while (true) {
        std::cout << "\n--- Password Manager Menu ---\n";
        std::cout << "1. Add New Password\n";
        std::cout << "2. Show Stored Passwords\n";
        std::cout << "3. Exit\n";
        std::cout << "Choose an option: ";
        std::cin >> choice;

        if (choice == 1) {
            // Add a new password
            std::string account, password;
            std::cout << "Enter account name (e.g., Gmail, Facebook): ";
            std::cin >> account;
            std::cout << "Enter password: ";
            std::cin >> password;

            pm.addPassword(account, password); // Add the new password to the manager
            std::cout << "Password added successfully!" << std::endl;
        }
        else if (choice == 2) {
            // Show stored passwords
            try {
                auto passwordDatabase = pm.getPasswordDatabase(); // Retrieve all stored passwords
                std::cout << "\n--- Stored Passwords ---\n";
                for (const auto& entry : passwordDatabase) {
                    std::cout << "Account: " << entry.first << ", Password: " << pm.getPassword(entry.first) << std::endl;
                }
            }
            catch (const std::runtime_error& e) {
                std::cout << "Error: " << e.what() << std::endl; // Handle any errors
            }
        }
        else if (choice == 3) {
            // Exit the program
            std::cout << "Exiting...\n";
            break;
        }
        else {
            std::cout << "Invalid option selected!" << std::endl;
        }
    }

    // Save the password database before exiting
    db.savePasswordDatabase(pm.getPasswordDatabase());

    return 0; // Indicate successful completion
}