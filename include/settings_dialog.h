#ifndef SETTINGS_DIALOG_H
#define SETTINGS_DIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QProgressBar>
#include "settings.h"

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget* parent = nullptr, const QString& databasePath = QString());

signals:
    void databaseRestored();

private slots:
    void onApplyClicked();
    void onOkClicked();
    void onCancelClicked();
    void onResetClicked();
    void onPasswordChanged();
    void onBrowseExportPath();
    void onBackupNowClicked();
    void onRestoreFromBackupClicked();

private:
    void setupUI();
    void loadSettings();
    void saveSettings();
    int calculatePasswordStrength(const QString& password);
    QString getPasswordStrengthText(int strength);
    
    // UI components
    QTabWidget* tabWidget;
    
    // General tab
    QComboBox* themeComboBox;
    QCheckBox* rememberLastDatabaseCheckBox;
    QCheckBox* showPasswordStrengthCheckBox;
    
    // Security tab
    QSpinBox* passwordMinLengthSpinBox;
    QCheckBox* autoLockCheckBox;
    QSpinBox* autoLockTimeoutSpinBox;
    QComboBox* encryptionMethodComboBox;
    QLineEdit* testPasswordLineEdit;
    QProgressBar* passwordStrengthBar;
    QLabel* passwordStrengthLabel;
    
    // Backup tab
    QCheckBox* autoBackupCheckBox;
    QSpinBox* backupRetentionSpinBox;
    QLineEdit* exportPathLineEdit;
    QPushButton* browseExportButton;
    QPushButton* backupNowButton;
    QPushButton* restoreFromBackupButton;
    
    // Buttons
    QPushButton* okButton;
    QPushButton* cancelButton;
    QPushButton* applyButton;
    QPushButton* resetButton;
    
    // Current database path for backup functionality
    QString currentDatabasePath;
};

#endif // SETTINGS_DIALOG_H
