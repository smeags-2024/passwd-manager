#ifndef PASSWORD_DATABASE_H
#define PASSWORD_DATABASE_H

#include "password_entry.h"
#include "crypto_utils.h"
#include <vector>
#include <string>
#include <memory>

class PasswordDatabase {
private:
    std::vector<PasswordEntry> entries;
    std::string masterPassword;
    std::string salt;
    std::string filePath;
    bool isAuthenticated;

public:
    PasswordDatabase(const std::string& dbPath);
    ~PasswordDatabase();
    
    bool authenticate(const std::string& password);
    bool setMasterPassword(const std::string& password);
    bool changeMasterPassword(const std::string& oldPassword, const std::string& newPassword);
    
    bool addEntry(const PasswordEntry& entry);
    bool updateEntry(const std::string& id, const PasswordEntry& entry);
    bool deleteEntry(const std::string& id);
    
    std::vector<PasswordEntry> getAllEntries() const;
    PasswordEntry* getEntry(const std::string& id);
    std::vector<PasswordEntry> searchEntries(const std::string& query) const;
    
    bool saveToFile();
    bool loadFromFile();
    
    void clearDatabase();
    bool isValidDatabase() const;
    
private:
    bool fileExists(const std::string& path) const;
    std::string encryptData(const std::string& data) const;
    std::string decryptData(const std::string& data) const;
};

#endif // PASSWORD_DATABASE_H
