#ifndef DATABASE_H
#define DATABASE_H

#include <string>
#include <unordered_map>

class Database {
public:
    // Saves the password database to a file
    void savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase);

    // Loads the password database from a file
    std::unordered_map<std::string, std::string> loadPasswordDatabase();
};

#endif // DATABASE_H
