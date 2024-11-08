#include "database.h"
#include "user.h"
#include "pwdStrength.h"
#include "smtp.h"
#include "recovery.h"
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <stdexcept>

// Function to generate a 6 character recovery code
std::string generateRecoveryCode() {
    // charset[] defines the set of characters the recovery code will be made of (63 characters including null char)
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    // Initalizes code, an empty string with a length of 6 to hold the generated code
    std::string code(6, ' ');
    // Create a vector named randomBytes with 6 unsigned characters to store random bytes for generating the code
    std::vector<unsigned char> randomBytes(6);
    // Use Openssl RAND_bytes function to generate 6 bytes randomly and store them in randomBytes (randomBytes.data(), 6)
    if (RAND_bytes(randomBytes.data(), 6) != 1) {       // If it returns anything other than 1 (!= 1), throw exception
        throw std::runtime_error("Error generating random bytes for recovery code.");
    }
    // Fill 6 positions in the code string with a random character from the charset array
    for (int i = 0; i < 6; ++i) {

        // randomBytes[i] is a vector of 6 random bytes
        // % restricts randomBytes[i] to an index within bounds of charset (0-61)
        // sizeof(charset) gives total byte size of the charset array (- 1 to account for null char)
        // Equation ends up as e.g. randomBytes[i] % 62 = 10, charset[10] = A, A gets assigned to i-th position in code
        code[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }
    return code;
}

// Function to handle account recovery (generating recovery code, updating recovery status and sending email)
void accountRecovery(const std::string& username) {
    try {
        // Initalize user object with user's username and empty password
        User user(username, "");
        // If user data cant be loaded, return early
        if (!user.loadUserData("", true)) {
            return; // Handle failure in UI
        }
        // Get user email and store in object
        std::string storedEmail = user.getEmail();
        // Check object for email, if no email exists, return early
        if (storedEmail.empty()) {
            return; // Handle missing email in UI
        }
        // Initialize Database object and recoveryCode string
        Database db(username);
        std::string recoveryCode;

        // Check db (user database file) to find if recovery is already in progress for this account
        if (!db.getRecoveryStatus(username, recoveryCode)) {
            // If no pre-existing recovery process found, call generateRecoveryCode() function and store result in string
            recoveryCode = generateRecoveryCode();
            // setRecoveryStatus updates user database file with a true recovery status flag, and the generated recovery code for comparison with user input
            db.setRecoveryStatus(username, true, recoveryCode);
            // Call sendRecoveryEmail, if email cant be sent, return early
            if (!sendRecoveryEmail(storedEmail, recoveryCode)) {
                return; // Handle email sending failure in UI
            }
        }
    }
    catch (const std::exception& e) {
        // Handle exceptions in UI
    }
}