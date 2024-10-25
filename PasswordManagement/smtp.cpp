#include <iostream>
#include <string>
#include <vector>
#include <openssl/rand.h>
#include <curl/curl.h>

// Function to generate a random recovery code
// Uses cryptographically secure random bytes to generate a code of specified length
std::string generateRecoveryCode(int length = 6) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string code;
    code.resize(length);
    std::vector<unsigned char> randomBytes(length);

    // Generate random bytes for the recovery code
    if (RAND_bytes(randomBytes.data(), length) != 1) {
        throw std::runtime_error("Error generating random bytes for recovery code.");
    }

    // Map random bytes to characters from the charset
    for (int i = 0; i < length; ++i) {
        code[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
    }

    return code;  // Return the generated recovery code
}

// Function to send a recovery email using Mailjet's API and libcurl
// Takes recipient email and the recovery code to be sent
bool sendRecoveryEmail(const std::string& email, const std::string& recoveryCode) {
    CURL* curl;
    CURLcode res;

    // Initialize curl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();  // Initialize a curl session

    if (curl) {
        // Mailjet API credentials (replace with environment variables or config in production)
        const std::string mailjetApiKey = "example";
        const std::string mailjetSecretKey = "example";

        // Set up recipient email
        struct curl_slist* recipients = curl_slist_append(nullptr, email.c_str());

        // Set up email headers
        struct curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");

        // Create JSON payload for the email
        std::string jsonPayload = R"({
            "Messages":[
                {
                    "From": {"Email": "tobijameshigginson@gmail.com", "Name": "Password Manager"},
                    "To": [{"Email": ")" + email + R"("}],
                    "Subject": "Password Recovery Code",
                    "TextPart": "Your recovery code is: )" + recoveryCode + R"("
                }
            ]
        })";

        // Set curl options for sending email via Mailjet's API
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  // Enable verbose output for debugging
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);  // Set headers (e.g., Content-Type)
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.mailjet.com/v3.1/send");  // Set Mailjet API endpoint
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);  // Use TLS 1.2 for secure connection
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);  // Use basic authentication
        curl_easy_setopt(curl, CURLOPT_USERNAME, mailjetApiKey.c_str());  // Set Mailjet API key
        curl_easy_setopt(curl, CURLOPT_PASSWORD, mailjetSecretKey.c_str());  // Set Mailjet secret key
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());  // Set the JSON payload as POST data
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);  // Set email recipient

        // Set CA certificate path for secure communication
        curl_easy_setopt(curl, CURLOPT_CAINFO, "openssl/tests/certs/cacert-2024-09-24.pem");  // Path to CA bundle for debug
        // curl_easy_setopt(curl, CURLOPT_CAINFO, "resources/cacert-2024-09-24.pem"); // Path to CA bundle for release

        // Perform the email request
        res = curl_easy_perform(curl);

        // Clean up resources
        curl_slist_free_all(recipients);  // Free the recipient list
        curl_slist_free_all(headers);  // Free the headers list
        curl_easy_cleanup(curl);  // Cleanup the curl session
        curl_global_cleanup();  // Clean up libcurl globally

        // Check if the request was successful
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            return false;  // Return false if email sending failed
        }

        return true;  // Email sent successfully
    }

    // Return false if curl could not be initialized
    return false;
}