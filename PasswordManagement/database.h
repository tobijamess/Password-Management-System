#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <unordered_map>

class Database {
public:
    // Constructor accepts the username to create a user-specific database
    Database(const std::string& username);

    // Creates an empty password database for a new user
    void createEmptyDatabase();

    static bool fileExists(const std::string& filename);

    bool savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase);
    std::unordered_map<std::string, std::string> loadPasswordDatabase();

    bool setRecoveryStatus(const std::string& username, bool inRecovery, const std::string& recoveryCode = "");
    bool getRecoveryStatus(const std::string& username, std::string& recoveryCode);

    bool clearPasswords();

private:
    std::string dbFilename;  // Stores the name of the user-specific database file
};

#endif // DATABASE_H