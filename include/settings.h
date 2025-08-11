#ifndef SETTINGS_H
#define SETTINGS_H

#include <QString>
#include <QSettings>
#include <memory>

class Settings {
public:
    enum class Theme {
        System,
        Dark,
        Light
    };
    
    enum class EncryptionMethod {
        AES256,
        ChaCha20_Poly1305,  // Modern stream cipher with authenticated encryption
        AES256_GCM,         // AES-256 with Galois/Counter Mode
        XORFallback
    };
    
    static Settings& instance();
    
    // Theme settings
    Theme getTheme() const;
    void setTheme(Theme theme);
    
    // Security settings
    int getPasswordMinLength() const;
    void setPasswordMinLength(int length);
    
    bool getAutoLock() const;
    void setAutoLock(bool enabled);
    
    int getAutoLockTimeout() const; // in minutes
    void setAutoLockTimeout(int timeout);
    
    EncryptionMethod getEncryptionMethod() const;
    void setEncryptionMethod(EncryptionMethod method);
    
    // Application settings
    bool getRememberLastDatabase() const;
    void setRememberLastDatabase(bool remember);
    
    QString getLastDatabasePath() const;
    void setLastDatabasePath(const QString& path);
    
    bool getShowPasswordStrength() const;
    void setShowPasswordStrength(bool show);
    
    // Backup settings
    bool getAutoBackup() const;
    void setAutoBackup(bool enabled);
    
    int getBackupRetentionDays() const;
    void setBackupRetentionDays(int days);
    
    // Import/Export settings
    QString getDefaultExportPath() const;
    void setDefaultExportPath(const QString& path);
    
    // Reset to defaults
    void resetToDefaults();
    
    // Save/Load settings
    void save();
    void load();

private:
    Settings();
    ~Settings() = default;
    Settings(const Settings&) = delete;
    Settings& operator=(const Settings&) = delete;
    
    std::unique_ptr<QSettings> settings;
    
    // Default values
    static constexpr int DEFAULT_PASSWORD_MIN_LENGTH = 6;
    static constexpr int DEFAULT_AUTO_LOCK_TIMEOUT = 15; // minutes
    static constexpr int DEFAULT_BACKUP_RETENTION_DAYS = 30;
};

#endif // SETTINGS_H
