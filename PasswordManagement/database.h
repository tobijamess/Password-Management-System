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

    // Checks if a database file exists for the user
    static bool doesDatabaseExist(const std::string& username);

    // Loads the password database from a user-specific file
    std::unordered_map<std::string, std::string> loadPasswordDatabase();

    // Saves the password database to a user-specific file
    bool savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase);

private:
    std::string dbFilename;  // Stores the name of the user-specific database file
};


#endif // DATABASE_H



