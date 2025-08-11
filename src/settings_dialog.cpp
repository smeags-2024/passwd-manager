#include "settings_dialog.h"
#include <QApplication>
#include <QStyleFactory>
#include <QPalette>
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <QRegularExpression>
#include <QDateTime>
#include <QFile>

SettingsDialog::SettingsDialog(QWidget* parent, const QString& databasePath) : QDialog(parent), currentDatabasePath(databasePath) {
    setWindowTitle("Settings");
    setMinimumSize(500, 400);
    setupUI();
    loadSettings();
}

void SettingsDialog::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Tab widget
    tabWidget = new QTabWidget();
    mainLayout->addWidget(tabWidget);
    
    // General tab
    QWidget* generalTab = new QWidget();
    QFormLayout* generalLayout = new QFormLayout(generalTab);
    
    themeComboBox = new QComboBox();
    themeComboBox->addItem("System Default", static_cast<int>(Settings::Theme::System));
    themeComboBox->addItem("Dark", static_cast<int>(Settings::Theme::Dark));
    themeComboBox->addItem("Light", static_cast<int>(Settings::Theme::Light));
    generalLayout->addRow("Theme:", themeComboBox);
    
    rememberLastDatabaseCheckBox = new QCheckBox("Remember last opened database");
    generalLayout->addRow(rememberLastDatabaseCheckBox);
    
    showPasswordStrengthCheckBox = new QCheckBox("Show password strength indicator");
    generalLayout->addRow(showPasswordStrengthCheckBox);
    
    tabWidget->addTab(generalTab, "General");
    
    // Security tab
    QWidget* securityTab = new QWidget();
    QVBoxLayout* securityMainLayout = new QVBoxLayout(securityTab);
    
    QGroupBox* passwordGroup = new QGroupBox("Password Requirements");
    QFormLayout* passwordLayout = new QFormLayout(passwordGroup);
    
    passwordMinLengthSpinBox = new QSpinBox();
    passwordMinLengthSpinBox->setRange(4, 50);
    passwordLayout->addRow("Minimum password length:", passwordMinLengthSpinBox);
    
    securityMainLayout->addWidget(passwordGroup);
    
    QGroupBox* lockGroup = new QGroupBox("Auto-Lock");
    QFormLayout* lockLayout = new QFormLayout(lockGroup);
    
    autoLockCheckBox = new QCheckBox("Enable auto-lock");
    lockLayout->addRow(autoLockCheckBox);
    
    autoLockTimeoutSpinBox = new QSpinBox();
    autoLockTimeoutSpinBox->setRange(1, 240);
    autoLockTimeoutSpinBox->setSuffix(" minutes");
    lockLayout->addRow("Lock after:", autoLockTimeoutSpinBox);
    
    securityMainLayout->addWidget(lockGroup);
    
    QGroupBox* encryptionGroup = new QGroupBox("Encryption");
    QFormLayout* encryptionLayout = new QFormLayout(encryptionGroup);
    
    encryptionMethodComboBox = new QComboBox();
    encryptionMethodComboBox->addItem("AES-256-CBC (Standard)", static_cast<int>(Settings::EncryptionMethod::AES256));
    encryptionMethodComboBox->addItem("ChaCha20-Poly1305 (Modern Stream Cipher)", static_cast<int>(Settings::EncryptionMethod::ChaCha20_Poly1305));
    encryptionMethodComboBox->addItem("AES-256-GCM (Authenticated Encryption)", static_cast<int>(Settings::EncryptionMethod::AES256_GCM));
    encryptionMethodComboBox->addItem("XOR (Legacy - Not Recommended)", static_cast<int>(Settings::EncryptionMethod::XORFallback));
    encryptionLayout->addRow("Encryption method:", encryptionMethodComboBox);
    
    // Add encryption description
    QLabel* encryptionDescLabel = new QLabel(
        "<b>Encryption Methods:</b><br>"
        "• <b>AES-256-CBC:</b> Industry standard, PBKDF2 key derivation<br>"
        "• <b>ChaCha20-Poly1305:</b> Modern stream cipher, resistant to timing attacks<br>"
        "• <b>AES-256-GCM:</b> Authenticated encryption, prevents tampering<br>"
        "• <b>XOR Legacy:</b> Basic encryption, not recommended for sensitive data"
    );
    encryptionDescLabel->setWordWrap(true);
    encryptionDescLabel->setStyleSheet("QLabel { color: #666; font-size: 10px; margin-top: 5px; }");
    encryptionLayout->addRow(encryptionDescLabel);
    
    securityMainLayout->addWidget(encryptionGroup);
    
    QGroupBox* testGroup = new QGroupBox("Password Strength Test");
    QFormLayout* testLayout = new QFormLayout(testGroup);
    
    testPasswordLineEdit = new QLineEdit();
    testPasswordLineEdit->setPlaceholderText("Enter a password to test its strength...");
    testPasswordLineEdit->setEchoMode(QLineEdit::Password);
    testLayout->addRow("Test password:", testPasswordLineEdit);
    
    passwordStrengthBar = new QProgressBar();
    passwordStrengthBar->setRange(0, 100);
    testLayout->addRow("Strength:", passwordStrengthBar);
    
    passwordStrengthLabel = new QLabel("Enter a password to see its strength");
    passwordStrengthLabel->setWordWrap(true);
    testLayout->addRow(passwordStrengthLabel);
    
    securityMainLayout->addWidget(testGroup);
    
    connect(testPasswordLineEdit, &QLineEdit::textChanged, this, &SettingsDialog::onPasswordChanged);
    
    tabWidget->addTab(securityTab, "Security");
    
    // Backup tab
    QWidget* backupTab = new QWidget();
    QFormLayout* backupLayout = new QFormLayout(backupTab);
    
    autoBackupCheckBox = new QCheckBox("Enable automatic backups");
    backupLayout->addRow(autoBackupCheckBox);
    
    backupRetentionSpinBox = new QSpinBox();
    backupRetentionSpinBox->setRange(1, 365);
    backupRetentionSpinBox->setSuffix(" days");
    backupLayout->addRow("Keep backups for:", backupRetentionSpinBox);
    
    QHBoxLayout* exportLayout = new QHBoxLayout();
    exportPathLineEdit = new QLineEdit();
    browseExportButton = new QPushButton("Browse...");
    exportLayout->addWidget(exportPathLineEdit);
    exportLayout->addWidget(browseExportButton);
    backupLayout->addRow("Default export path:", exportLayout);
    
    // Manual backup section
    QHBoxLayout* backupButtonsLayout = new QHBoxLayout();
    backupNowButton = new QPushButton("Backup Now");
    backupNowButton->setToolTip("Create a manual backup of your password database");
    restoreFromBackupButton = new QPushButton("Restore from Backup");
    restoreFromBackupButton->setToolTip("Restore your password database from a backup file");
    backupButtonsLayout->addWidget(backupNowButton);
    backupButtonsLayout->addWidget(restoreFromBackupButton);
    backupLayout->addRow("Manual backup:", backupButtonsLayout);
    
    connect(browseExportButton, &QPushButton::clicked, this, &SettingsDialog::onBrowseExportPath);
    connect(backupNowButton, &QPushButton::clicked, this, &SettingsDialog::onBackupNowClicked);
    connect(restoreFromBackupButton, &QPushButton::clicked, this, &SettingsDialog::onRestoreFromBackupClicked);
    
    tabWidget->addTab(backupTab, "Backup & Export");
    
    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    resetButton = new QPushButton("Reset to Defaults");
    buttonLayout->addWidget(resetButton);
    buttonLayout->addStretch();
    
    okButton = new QPushButton("OK");
    cancelButton = new QPushButton("Cancel");
    applyButton = new QPushButton("Apply");
    
    okButton->setDefault(true);
    
    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(applyButton);
    
    mainLayout->addLayout(buttonLayout);
    
    // Connect buttons
    connect(okButton, &QPushButton::clicked, this, &SettingsDialog::onOkClicked);
    connect(cancelButton, &QPushButton::clicked, this, &SettingsDialog::onCancelClicked);
    connect(applyButton, &QPushButton::clicked, this, &SettingsDialog::onApplyClicked);
    connect(resetButton, &QPushButton::clicked, this, &SettingsDialog::onResetClicked);
}

void SettingsDialog::loadSettings() {
    Settings& settings = Settings::instance();
    
    // General
    themeComboBox->setCurrentIndex(themeComboBox->findData(static_cast<int>(settings.getTheme())));
    rememberLastDatabaseCheckBox->setChecked(settings.getRememberLastDatabase());
    showPasswordStrengthCheckBox->setChecked(settings.getShowPasswordStrength());
    
    // Security
    passwordMinLengthSpinBox->setValue(settings.getPasswordMinLength());
    autoLockCheckBox->setChecked(settings.getAutoLock());
    autoLockTimeoutSpinBox->setValue(settings.getAutoLockTimeout());
    encryptionMethodComboBox->setCurrentIndex(encryptionMethodComboBox->findData(static_cast<int>(settings.getEncryptionMethod())));
    
    // Backup
    autoBackupCheckBox->setChecked(settings.getAutoBackup());
    backupRetentionSpinBox->setValue(settings.getBackupRetentionDays());
    exportPathLineEdit->setText(settings.getDefaultExportPath());
}

void SettingsDialog::saveSettings() {
    Settings& settings = Settings::instance();
    
    // General
    settings.setTheme(static_cast<Settings::Theme>(themeComboBox->currentData().toInt()));
    settings.setRememberLastDatabase(rememberLastDatabaseCheckBox->isChecked());
    settings.setShowPasswordStrength(showPasswordStrengthCheckBox->isChecked());
    
    // Security
    settings.setPasswordMinLength(passwordMinLengthSpinBox->value());
    settings.setAutoLock(autoLockCheckBox->isChecked());
    settings.setAutoLockTimeout(autoLockTimeoutSpinBox->value());
    settings.setEncryptionMethod(static_cast<Settings::EncryptionMethod>(encryptionMethodComboBox->currentData().toInt()));
    
    // Backup
    settings.setAutoBackup(autoBackupCheckBox->isChecked());
    settings.setBackupRetentionDays(backupRetentionSpinBox->value());
    settings.setDefaultExportPath(exportPathLineEdit->text());
    
    settings.save();
}

void SettingsDialog::onApplyClicked() {
    saveSettings();
}

void SettingsDialog::onOkClicked() {
    saveSettings();
    accept();
}

void SettingsDialog::onCancelClicked() {
    reject();
}

void SettingsDialog::onResetClicked() {
    int ret = QMessageBox::question(this, "Reset Settings", 
                                   "Are you sure you want to reset all settings to their default values?",
                                   QMessageBox::Yes | QMessageBox::No);
    if (ret == QMessageBox::Yes) {
        Settings::instance().resetToDefaults();
        loadSettings();
    }
}

void SettingsDialog::onPasswordChanged() {
    QString password = testPasswordLineEdit->text();
    int strength = calculatePasswordStrength(password);
    
    passwordStrengthBar->setValue(strength);
    passwordStrengthLabel->setText(getPasswordStrengthText(strength));
    
    // Update progress bar color based on strength
    QString styleSheet;
    if (strength < 30) {
        styleSheet = "QProgressBar::chunk { background-color: #ff4444; }";
    } else if (strength < 60) {
        styleSheet = "QProgressBar::chunk { background-color: #ffaa00; }";
    } else if (strength < 80) {
        styleSheet = "QProgressBar::chunk { background-color: #88cc00; }";
    } else {
        styleSheet = "QProgressBar::chunk { background-color: #00aa00; }";
    }
    passwordStrengthBar->setStyleSheet(styleSheet);
}

void SettingsDialog::onBrowseExportPath() {
    QString currentPath = exportPathLineEdit->text();
    if (currentPath.isEmpty()) {
        currentPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    }
    
    QString path = QFileDialog::getExistingDirectory(this, "Select Default Export Directory", currentPath);
    if (!path.isEmpty()) {
        exportPathLineEdit->setText(path);
    }
}

int SettingsDialog::calculatePasswordStrength(const QString& password) {
    if (password.isEmpty()) return 0;
    
    int score = 0;
    
    // Length bonus
    score += std::min(static_cast<int>(password.length()) * 2, 25);
    
    // Character variety
    bool hasLower = password.contains(QRegularExpression("[a-z]"));
    bool hasUpper = password.contains(QRegularExpression("[A-Z]"));
    bool hasNumber = password.contains(QRegularExpression("[0-9]"));
    bool hasSymbol = password.contains(QRegularExpression("[^a-zA-Z0-9]"));
    
    int variety = hasLower + hasUpper + hasNumber + hasSymbol;
    score += variety * 10;
    
    // Length categories
    if (password.length() >= 8) score += 5;
    if (password.length() >= 12) score += 5;
    if (password.length() >= 16) score += 5;
    
    // Penalty for common patterns
    if (password.contains(QRegularExpression("123|abc|qwe", QRegularExpression::CaseInsensitiveOption))) {
        score -= 10;
    }
    
    // Bonus for mixed case next to each other
    if (password.contains(QRegularExpression("[a-z][A-Z]|[A-Z][a-z]"))) {
        score += 5;
    }
    
    return std::max(0, std::min(score, 100));
}

QString SettingsDialog::getPasswordStrengthText(int strength) {
    if (strength < 30) {
        return "Weak - Consider using a longer password with mixed characters";
    } else if (strength < 60) {
        return "Fair - Add more character variety for better security";
    } else if (strength < 80) {
        return "Good - This password provides decent security";
    } else {
        return "Strong - Excellent password security";
    }
}

void SettingsDialog::onBackupNowClicked() {
    // Use the current database path if available
    QString databasePath = currentDatabasePath;
    
    // Fallback to settings or default path if current path is empty
    if (databasePath.isEmpty()) {
        Settings& settings = Settings::instance();
        databasePath = settings.getLastDatabasePath();
        
        if (databasePath.isEmpty()) {
            QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
            databasePath = dataPath + "/passwords.db";
        }
    }
    
    // Check if database file exists
    QFile databaseFile(databasePath);
    if (!databaseFile.exists()) {
        QMessageBox::warning(this, "Backup Failed", 
                           "Database file not found. Please open a database first.");
        return;
    }
    
    // Get backup directory (use export path if set, otherwise use documents)
    QString backupDir = exportPathLineEdit->text();
    if (backupDir.isEmpty()) {
        backupDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    }
    
    // Create timestamp for backup filename
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    QString backupFileName = QString("passwords_backup_%1.db").arg(timestamp);
    QString backupPath = backupDir + "/" + backupFileName;
    
    // Ask user for backup location
    QString selectedPath = QFileDialog::getSaveFileName(this, 
                                                       "Save Backup As", 
                                                       backupPath,
                                                       "Database Files (*.db);;All Files (*)");
    
    if (selectedPath.isEmpty()) {
        return; // User cancelled
    }
    
    // Copy the database file
    if (databaseFile.copy(selectedPath)) {
        QMessageBox::information(this, "Backup Successful", 
                               QString("Database backup created successfully:\n%1").arg(selectedPath));
    } else {
        QMessageBox::critical(this, "Backup Failed", 
                            QString("Failed to create backup. Error:\n%1").arg(databaseFile.errorString()));
    }
}

void SettingsDialog::onRestoreFromBackupClicked() {
    // Warn user about overwriting current database
    QMessageBox::StandardButton reply = QMessageBox::warning(this, 
                                                             "Restore from Backup", 
                                                             "This will replace your current password database with the backup file.\n\n"
                                                             "Make sure to backup your current database first if you want to keep it.\n\n"
                                                             "Do you want to continue?",
                                                             QMessageBox::Yes | QMessageBox::No,
                                                             QMessageBox::No);
    
    if (reply != QMessageBox::Yes) {
        return;
    }
    
    // Get backup directory (use export path if set, otherwise use documents)
    QString backupDir = exportPathLineEdit->text();
    if (backupDir.isEmpty()) {
        backupDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    }
    
    // Ask user to select backup file
    QString backupPath = QFileDialog::getOpenFileName(this, 
                                                     "Select Backup File to Restore", 
                                                     backupDir,
                                                     "Database Files (*.db);;All Files (*)");
    
    if (backupPath.isEmpty()) {
        return; // User cancelled
    }
    
    // Verify the backup file exists and is readable
    QFile backupFile(backupPath);
    if (!backupFile.exists()) {
        QMessageBox::critical(this, "Restore Failed", "Backup file not found.");
        return;
    }
    
    if (!backupFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Restore Failed", 
                            QString("Cannot read backup file. Error:\n%1").arg(backupFile.errorString()));
        return;
    }
    backupFile.close();
    
    // Get the current database path
    QString databasePath = currentDatabasePath;
    if (databasePath.isEmpty()) {
        Settings& settings = Settings::instance();
        databasePath = settings.getLastDatabasePath();
        
        if (databasePath.isEmpty()) {
            QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
            databasePath = dataPath + "/passwords.db";
        }
    }
    
    // Remove current database file if it exists
    QFile currentDatabase(databasePath);
    if (currentDatabase.exists()) {
        if (!currentDatabase.remove()) {
            QMessageBox::critical(this, "Restore Failed", 
                                QString("Cannot remove current database file. Error:\n%1").arg(currentDatabase.errorString()));
            return;
        }
    }
    
    // Copy backup file to database location
    if (backupFile.copy(databasePath)) {
        QMessageBox::information(this, "Restore Successful", 
                               "Database restored successfully from backup.\n\n"
                               "The entries will be refreshed automatically.");
        
        // Emit signal to reload the database
        emit databaseRestored();
        
        // Close the settings dialog
        accept();
    } else {
        QMessageBox::critical(this, "Restore Failed", 
                            QString("Failed to restore from backup. Error:\n%1").arg(backupFile.errorString()));
    }
}
