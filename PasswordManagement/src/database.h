#ifndef DATABASE_H
#define DATABASE_H
#include <string>
#include <unordered_map>

class Database {
public:
    Database(const std::string& username);
    void createEmptyDatabase();
    static bool fileExists(const std::string& filename);
    bool savePasswordDatabase(const std::unordered_map<std::string, std::string>& passwordDatabase);
    std::unordered_map<std::string, std::string> loadPasswordDatabase();
    bool setRecoveryStatus(const std::string& username, bool inRecovery, const std::string& recoveryCode = "");
    bool getRecoveryStatus(const std::string& username, std::string& recoveryCode);
    bool validateRecoveryCode(const std::string& username, std::string& inputCode);
    bool clearPasswords();
private:
    std::string dbFilename;
};
#endif