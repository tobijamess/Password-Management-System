#include "database.h"
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

Database::Database(const std::string& username)
    : dbFilename(username + "_data.json") {}

bool Database::fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

void Database::createEmptyDatabase() {
    std::ofstream dbFile(dbFilename);
    if (dbFile) {
        json emptyDb = json::array();
        dbFile << emptyDb.dump(4);
    }
}

bool Database::savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase) {
    std::ifstream file(dbFilename);
    json userData;
    if (file) file >> userData;

    userData["passwords"] = passwordDatabase;

    std::ofstream outFile(dbFilename);
    if (!outFile) return false;

    outFile << userData.dump(4); // Write pretty-formatted JSON
    return true;
}

std::unordered_map<std::string, std::string> Database::loadPasswordDatabase() {
    std::unordered_map<std::string, std::string> passwordDatabase;
    std::ifstream file(dbFilename);

    if (file) {
        json userData;
        file >> userData;

        for (auto& item : userData["passwords"].items()) {
            std::string key = item.key();
            std::string value = item.value();
            passwordDatabase[key] = value;
        }
    }
    return passwordDatabase;
}