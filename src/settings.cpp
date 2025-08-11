#include "settings.h"
#include <QStandardPaths>
#include <QDir>

Settings& Settings::instance() {
    static Settings instance;
    return instance;
}

Settings::Settings() {
    QString configPath = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);
    QString appConfigPath = configPath + "/PasswordManager";
    
    // Ensure config directory exists
    QDir().mkpath(appConfigPath);
    
    settings = std::make_unique<QSettings>(appConfigPath + "/settings.ini", QSettings::IniFormat);
    load();
}

Settings::Theme Settings::getTheme() const {
    return static_cast<Theme>(settings->value("appearance/theme", static_cast<int>(Theme::System)).toInt());
}

void Settings::setTheme(Theme theme) {
    settings->setValue("appearance/theme", static_cast<int>(theme));
}

int Settings::getPasswordMinLength() const {
    return settings->value("security/passwordMinLength", DEFAULT_PASSWORD_MIN_LENGTH).toInt();
}

void Settings::setPasswordMinLength(int length) {
    settings->setValue("security/passwordMinLength", length);
}

bool Settings::getAutoLock() const {
    return settings->value("security/autoLock", true).toBool();
}

void Settings::setAutoLock(bool enabled) {
    settings->setValue("security/autoLock", enabled);
}

int Settings::getAutoLockTimeout() const {
    return settings->value("security/autoLockTimeout", DEFAULT_AUTO_LOCK_TIMEOUT).toInt();
}

void Settings::setAutoLockTimeout(int timeout) {
    settings->setValue("security/autoLockTimeout", timeout);
}

Settings::EncryptionMethod Settings::getEncryptionMethod() const {
    return static_cast<EncryptionMethod>(settings->value("security/encryptionMethod", static_cast<int>(EncryptionMethod::ChaCha20_Poly1305)).toInt());
}

void Settings::setEncryptionMethod(EncryptionMethod method) {
    settings->setValue("security/encryptionMethod", static_cast<int>(method));
}

bool Settings::getRememberLastDatabase() const {
    return settings->value("application/rememberLastDatabase", true).toBool();
}

void Settings::setRememberLastDatabase(bool remember) {
    settings->setValue("application/rememberLastDatabase", remember);
}

QString Settings::getLastDatabasePath() const {
    return settings->value("application/lastDatabasePath", "").toString();
}

void Settings::setLastDatabasePath(const QString& path) {
    settings->setValue("application/lastDatabasePath", path);
}

bool Settings::getShowPasswordStrength() const {
    return settings->value("application/showPasswordStrength", true).toBool();
}

void Settings::setShowPasswordStrength(bool show) {
    settings->setValue("application/showPasswordStrength", show);
}

bool Settings::getAutoBackup() const {
    return settings->value("backup/autoBackup", false).toBool();
}

void Settings::setAutoBackup(bool enabled) {
    settings->setValue("backup/autoBackup", enabled);
}

int Settings::getBackupRetentionDays() const {
    return settings->value("backup/retentionDays", DEFAULT_BACKUP_RETENTION_DAYS).toInt();
}

void Settings::setBackupRetentionDays(int days) {
    settings->setValue("backup/retentionDays", days);
}

QString Settings::getDefaultExportPath() const {
    return settings->value("export/defaultPath", QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)).toString();
}

void Settings::setDefaultExportPath(const QString& path) {
    settings->setValue("export/defaultPath", path);
}

void Settings::resetToDefaults() {
    settings->clear();
    load(); // Load defaults
}

void Settings::save() {
    settings->sync();
}

void Settings::load() {
    // This method is called from constructor and resetToDefaults
    // Values are loaded automatically when accessed via value() method
    // with default fallback values
}
