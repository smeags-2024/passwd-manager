#include "password_database.h"
#include "settings.h"
#include "logger.h"
#include <fstream>
#include <iostream>
#include <algorithm>

PasswordDatabase::PasswordDatabase(const std::string& dbPath) 
    : filePath(dbPath), isAuthenticated(false) {
    if (fileExists(filePath)) {
        // Load salt from file for existing database
        std::ifstream file(filePath, std::ios::binary);
        if (file.is_open()) {
            std::string line;
            if (std::getline(file, line) && line.substr(0, 5) == "SALT:") {
                salt = line.substr(5);
            }
            file.close();
        }
    } else {
        // Generate new salt for new database
        salt = CryptoUtils::generateSalt();
    }
}

PasswordDatabase::~PasswordDatabase() {
    clearDatabase();
}

bool PasswordDatabase::authenticate(const std::string& password) {
    if (!fileExists(filePath)) {
        return false;
    }
    
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::getline(file, line); // Skip salt line
    
    if (std::getline(file, line) && line.substr(0, 5) == "HASH:") {
        std::string storedHash = line.substr(5);
        if (CryptoUtils::verifyPassword(password, storedHash, salt)) {
            masterPassword = password;
            isAuthenticated = true;
            file.close();
            loadFromFile();
            return true;
        }
    }
    
    file.close();
    return false;
}

bool PasswordDatabase::setMasterPassword(const std::string& password) {
    if (fileExists(filePath)) {
        return false; // Database already exists
    }
    
    masterPassword = password;
    isAuthenticated = true;
    return saveToFile();
}

bool PasswordDatabase::changeMasterPassword(const std::string& oldPassword, const std::string& newPassword) {
    if (!isAuthenticated || !authenticate(oldPassword)) {
        return false;
    }
    
    masterPassword = newPassword;
    return saveToFile();
}

bool PasswordDatabase::addEntry(const PasswordEntry& entry) {
    if (!isAuthenticated) {
        return false;
    }
    
    LOG_INFO(QString("ADDING entry: %1 (ID: %2)").arg(QString::fromStdString(entry.title)).arg(QString::fromStdString(entry.id)));
    LOG_INFO(QString("Entries count before adding: %1").arg(entries.size()));
    
    entries.push_back(entry);
    
    LOG_INFO(QString("Entries count after adding: %1").arg(entries.size()));
    
    // Auto-save after adding
    if (!saveToFile()) {
        LOG_ERROR("Failed to save database after adding entry");
        return false;
    }
    
    return true;
}

bool PasswordDatabase::updateEntry(const std::string& id, const PasswordEntry& entry) {
    if (!isAuthenticated) {
        return false;
    }
    
    LOG_INFO(QString("UPDATING entry with ID: %1 to title: %2").arg(QString::fromStdString(id)).arg(QString::fromStdString(entry.title)));
    LOG_INFO(QString("Entries count before update: %1").arg(entries.size()));
    
    auto it = std::find_if(entries.begin(), entries.end(),
                          [&id](const PasswordEntry& e) { return e.id == id; });
    
    if (it != entries.end()) {
        LOG_INFO(QString("Found existing entry for update: %1").arg(QString::fromStdString(it->title)));
        
        // Preserve the original ID and creation time
        std::string originalId = it->id;
        std::time_t originalCreated = it->created;
        
        // Update the entry
        *it = entry;
        
        // Restore the original ID and creation time
        it->id = originalId;
        it->created = originalCreated;
        it->modified = std::time(nullptr);
        
        LOG_INFO(QString("Entry updated successfully, saving to file"));
        
        return saveToFile();
    } else {
        LOG_ERROR(QString("Entry with ID %1 not found for update").arg(QString::fromStdString(id)));
    }
    
    LOG_INFO(QString("Entries count after update: %1").arg(entries.size()));
    return false;
}

bool PasswordDatabase::deleteEntry(const std::string& id) {
    if (!isAuthenticated) {
        return false;
    }
    
    // Add extensive logging to track deletions
    LOG_INFO(QString("DELETE REQUESTED for entry ID: %1").arg(QString::fromStdString(id)));
    LOG_INFO(QString("Entries count before deletion: %1").arg(entries.size()));
    
    // Log stack trace or calling function if possible
    LOG_INFO("DELETION CALL STACK - THIS SHOULD NOT HAPPEN ACCIDENTALLY!");
    
    auto it = std::find_if(entries.begin(), entries.end(),
                          [&id](const PasswordEntry& e) { return e.id == id; });
    
    if (it != entries.end()) {
        LOG_INFO(QString("DELETING entry: %1").arg(QString::fromStdString(it->title)));
        entries.erase(it);
        LOG_INFO(QString("Entries count after deletion: %1").arg(entries.size()));
        
        // Auto-save after deletion
        if (!saveToFile()) {
            LOG_ERROR("Failed to save database after entry deletion");
            return false;
        }
        return true;
    } else {
        LOG_ERROR(QString("Entry with ID %1 not found for deletion").arg(QString::fromStdString(id)));
        return false;
    }
}

std::vector<PasswordEntry> PasswordDatabase::getAllEntries() const {
    if (!isAuthenticated) {
        return {};
    }
    return entries;
}

PasswordEntry* PasswordDatabase::getEntry(const std::string& id) {
    if (!isAuthenticated) {
        return nullptr;
    }
    
    auto it = std::find_if(entries.begin(), entries.end(),
                          [&id](const PasswordEntry& e) { return e.id == id; });
    
    return (it != entries.end()) ? &(*it) : nullptr;
}

std::vector<PasswordEntry> PasswordDatabase::searchEntries(const std::string& query) const {
    if (!isAuthenticated) {
        return {};
    }
    
    std::vector<PasswordEntry> results;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    
    for (const auto& entry : entries) {
        std::string lowerTitle = entry.title;
        std::string lowerUsername = entry.username;
        std::string lowerUrl = entry.url;
        
        std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::tolower);
        std::transform(lowerUsername.begin(), lowerUsername.end(), lowerUsername.begin(), ::tolower);
        std::transform(lowerUrl.begin(), lowerUrl.end(), lowerUrl.begin(), ::tolower);
        
        if (lowerTitle.find(lowerQuery) != std::string::npos ||
            lowerUsername.find(lowerQuery) != std::string::npos ||
            lowerUrl.find(lowerQuery) != std::string::npos) {
            results.push_back(entry);
        }
    }
    
    return results;
}

bool PasswordDatabase::saveToFile() {
    if (!isAuthenticated) {
        return false;
    }
    
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Write salt
    file << "SALT:" << salt << std::endl;
    
    // Write password hash
    std::string passwordHash = CryptoUtils::hashPassword(masterPassword, salt);
    file << "HASH:" << passwordHash << std::endl;
    
    // Write encrypted entries
    for (const auto& entry : entries) {
        std::string entryData = entry.toString();
        std::string encryptedData = encryptData(entryData);
        file << "ENTRY:" << encryptedData << std::endl;
    }
    
    file.close();
    return true;
}

bool PasswordDatabase::loadFromFile() {
    if (!isAuthenticated || !fileExists(filePath)) {
        return false;
    }
    
    entries.clear();
    
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    bool needsSave = false;
    
    while (std::getline(file, line)) {
        if (line.substr(0, 6) == "ENTRY:") {
            std::string encryptedData = line.substr(6);
            std::string decryptedData = decryptData(encryptedData);
            
            // Skip entries that failed to decrypt
            if (decryptedData.empty()) {
                LOG_ERROR("Failed to decrypt entry, skipping");
                continue;
            }

            PasswordEntry entry = PasswordEntry::fromString(decryptedData);
            
            // Skip entries with empty titles (indicates corruption)
            if (entry.title.empty()) {
                LOG_ERROR("Entry has empty title after decryption, skipping");
                continue;
            }
            
            // Ensure entry has a valid ID
            if (entry.id.empty()) {
                entry.generateId();
                needsSave = true;
            }
            
            // Ensure ID is unique
            while (getEntry(entry.id) != nullptr) {
                entry.generateId();
                needsSave = true;
            }
            
            entries.push_back(entry);
            LOG_INFO(QString("Successfully loaded entry: %1").arg(QString::fromStdString(entry.title)));
        }
    }
    
    file.close();
    
    // Save back to file if we generated any IDs
    if (needsSave) {
        saveToFile();
    }
    
    return true;
}

void PasswordDatabase::clearDatabase() {
    entries.clear();
    masterPassword.clear();
    isAuthenticated = false;
}

bool PasswordDatabase::isValidDatabase() const {
    return fileExists(filePath);
}

bool PasswordDatabase::fileExists(const std::string& path) const {
    std::ifstream file(path);
    return file.good();
}

std::string PasswordDatabase::encryptData(const std::string& data) const {
    Settings& settings = Settings::instance();
    Settings::EncryptionMethod method = settings.getEncryptionMethod();
    
    switch (method) {
        case Settings::EncryptionMethod::ChaCha20_Poly1305:
            return CryptoUtils::encryptChaCha20(data, masterPassword);
        case Settings::EncryptionMethod::AES256_GCM:
            return CryptoUtils::encryptAESGCM(data, masterPassword);
        case Settings::EncryptionMethod::XORFallback:
            // Note: XOR is not recommended for production use
            return CryptoUtils::encrypt(data, masterPassword); // Falls back to basic AES
        case Settings::EncryptionMethod::AES256:
        default:
            return CryptoUtils::encrypt(data, masterPassword);
    }
}

std::string PasswordDatabase::decryptData(const std::string& data) const {
    Settings& settings = Settings::instance();
    Settings::EncryptionMethod method = settings.getEncryptionMethod();
    
    LOG_INFO(QString("Attempting to decrypt data with current method: %1").arg(static_cast<int>(method)));
    
    // Try the current method first
    std::string result;
    try {
        switch (method) {
            case Settings::EncryptionMethod::ChaCha20_Poly1305:
                result = CryptoUtils::decryptChaCha20(data, masterPassword);
                if (!result.empty()) {
                    LOG_INFO("Successfully decrypted with ChaCha20");
                    return result;
                }
                break;
            case Settings::EncryptionMethod::AES256_GCM:
                result = CryptoUtils::decryptAESGCM(data, masterPassword);
                if (!result.empty()) {
                    LOG_INFO("Successfully decrypted with AES-GCM");
                    return result;
                }
                break;
            case Settings::EncryptionMethod::XORFallback:
                result = CryptoUtils::decrypt(data, masterPassword);
                if (!result.empty()) {
                    LOG_INFO("Successfully decrypted with XOR/AES fallback");
                    return result;
                }
                break;
            case Settings::EncryptionMethod::AES256:
            default:
                result = CryptoUtils::decrypt(data, masterPassword);
                if (!result.empty()) {
                    LOG_INFO("Successfully decrypted with AES-256");
                    return result;
                }
                break;
        }
    } catch (const std::exception& e) {
        LOG_ERROR(QString("Current method failed: %1").arg(e.what()));
    }
    
    LOG_INFO("Current method failed, trying fallback methods...");
    
    // If the current method failed, try all other methods for backward compatibility
    // Try AES-256 standard (most common)
    try {
        result = CryptoUtils::decrypt(data, masterPassword);
        if (!result.empty()) {
            LOG_INFO("Successfully decrypted with AES-256 fallback");
            return result;
        }
    } catch (const std::exception& e) {
        LOG_ERROR(QString("AES-256 fallback failed: %1").arg(e.what()));
    }
    
    // Try ChaCha20 if not already tried
    if (method != Settings::EncryptionMethod::ChaCha20_Poly1305) {
        try {
            result = CryptoUtils::decryptChaCha20(data, masterPassword);
            if (!result.empty()) {
                LOG_INFO("Successfully decrypted with ChaCha20 fallback");
                return result;
            }
        } catch (const std::exception& e) {
            LOG_ERROR(QString("ChaCha20 fallback failed: %1").arg(e.what()));
        }
    }
    
    // Try AES-GCM if not already tried
    if (method != Settings::EncryptionMethod::AES256_GCM) {
        try {
            result = CryptoUtils::decryptAESGCM(data, masterPassword);
            if (!result.empty()) {
                LOG_INFO("Successfully decrypted with AES-GCM fallback");
                return result;
            }
        } catch (const std::exception& e) {
            LOG_ERROR(QString("AES-GCM fallback failed: %1").arg(e.what()));
        }
    }
    
    LOG_ERROR("All decryption methods failed");
    // If all methods failed, return empty string
    return "";
}
