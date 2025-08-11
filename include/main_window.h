#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <QtWidgets/QMainWindow>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QProgressBar>
#include <memory>
#include "password_database.h"

class QAction;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void newDatabase();
    void openDatabase();
    void closeDatabase();
    void changePassword();
    void addEntry();
    void editEntry();
    void deleteEntry();
    void searchEntries();
    void onEntrySelected();
    void generatePassword();
    void togglePasswordVisibility();
    void copyUsername();
    void copyPassword();
    void showSettings();
    void onPasswordChanged();
    void about();

private:
    void setupUI();
    void setupMenuBar();
    void connectSignals();
    void refreshEntryList();
    void clearEntryDetails();
    void showEntryDetails(const PasswordEntry& entry);
    void updateEntryDetails();
    bool authenticateUser();
    bool promptForNewPassword();
    QString getProjectDataPath() const;  // New helper function
    void updateUIState(bool databaseOpen);  // Update UI based on database state
    
    // UI Components
    QWidget *centralWidget;
    QSplitter *mainSplitter;
    
    // Left panel - Entry list
    QWidget *leftPanel;
    QVBoxLayout *leftLayout;
    QLineEdit *searchBox;
    QListWidget *entryList;
    QPushButton *addButton;
    QPushButton *editButton;
    QPushButton *deleteButton;
    
    // Right panel - Entry details
    QWidget *rightPanel;
    QVBoxLayout *rightLayout;
    QGroupBox *detailsGroup;
    QLineEdit *titleEdit;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QLineEdit *urlEdit;
    QTextEdit *notesEdit;
    QCheckBox *showPasswordCheck;
    QPushButton *generatePasswordButton;
    
    // Password strength indicator
    QProgressBar *passwordStrengthBar;
    QLabel *passwordStrengthLabel;
    
    QPushButton *copyUsernameButton;
    QPushButton *copyPasswordButton;
    QPushButton *saveButton;
    QPushButton *cancelButton;
    
    // Menu actions
    QAction *newAction;
    QAction *openAction;
    QAction *closeAction;
    QAction *changePasswordAction;
    QAction *settingsAction;
    QAction *exitAction;
    QAction *aboutAction;
    
    // Database
    std::unique_ptr<PasswordDatabase> database;
    QString currentDatabasePath;
    bool isEditing;
    std::string currentEntryId;
    bool isDeletingEntry; // Flag to prevent selection events during deletion
};

#endif // MAIN_WINDOW_H
