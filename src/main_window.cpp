#include "main_window.h"
#include "logger.h"
#include "settings_dialog.h"
#include "settings.h"
#include "crypto_utils.h"
#include <QtWidgets/QApplication>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QProgressBar>
#include <QtGui/QClipboard>
#include <QtCore/QStandardPaths>
#include <QtCore/QDir>
#include <QtCore/QCoreApplication>
#include <random>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), isEditing(false), isDeletingEntry(false) {
    LOG_INFO("Initializing main window...");
    
    setupUI();
    setupMenuBar();
    connectSignals();
    
    // Set window properties
    setWindowTitle("Password Manager - Secure Password Storage");
    setMinimumSize(900, 650);
    resize(1100, 750);
    
    // Set window icon (if available)
    setWindowIcon(QIcon::fromTheme("dialog-password"));
    
    // Use project data directory instead of system directories
    QString dataPath = getProjectDataPath();
    QDir().mkpath(dataPath);
    QString dbPath = dataPath + "/passwords.db";
    
    LOG_INFO(QString("Using data path: %1").arg(dataPath));
    LOG_INFO(QString("Default database path: %1").arg(dbPath));
    
    if (QFile::exists(dbPath)) {
        LOG_INFO("Found existing database, attempting to load...");
        currentDatabasePath = dbPath;
        database = std::make_unique<PasswordDatabase>(dbPath.toStdString());
        if (authenticateUser()) {
            refreshEntryList();
            updateUIState(true);
            statusBar()->showMessage("Database loaded successfully - Ready", 0);
            LOG_INFO("Database loaded and authenticated successfully");
        } else {
            LOG_WARNING("Failed to authenticate with existing database");
        }
    } else {
        updateUIState(false);
        statusBar()->showMessage("Ready - No database found. Create or open a database.", 0);
        LOG_INFO("No existing database found");
    }
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUI() {
    centralWidget = new QWidget;
    setCentralWidget(centralWidget);
    
    mainSplitter = new QSplitter(Qt::Horizontal);
    
    // Left Panel
    leftPanel = new QWidget;
    leftLayout = new QVBoxLayout(leftPanel);
    
    searchBox = new QLineEdit;
    searchBox->setPlaceholderText("Search entries...");
    leftLayout->addWidget(searchBox);
    
    entryList = new QListWidget;
    leftLayout->addWidget(entryList);
    
    QHBoxLayout *buttonLayout = new QHBoxLayout;
    addButton = new QPushButton("Add");
    editButton = new QPushButton("Edit");
    deleteButton = new QPushButton("Delete");
    
    buttonLayout->addWidget(addButton);
    buttonLayout->addWidget(editButton);
    buttonLayout->addWidget(deleteButton);
    leftLayout->addLayout(buttonLayout);
    
    // Right Panel
    rightPanel = new QWidget;
    rightLayout = new QVBoxLayout(rightPanel);
    
    detailsGroup = new QGroupBox("Entry Details");
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsGroup);
    
    // Form layout
    detailsLayout->addWidget(new QLabel("Title:"));
    titleEdit = new QLineEdit;
    detailsLayout->addWidget(titleEdit);
    
    detailsLayout->addWidget(new QLabel("Username:"));
    QHBoxLayout *usernameLayout = new QHBoxLayout;
    usernameEdit = new QLineEdit;
    copyUsernameButton = new QPushButton("Copy");
    copyUsernameButton->setMaximumWidth(60);
    usernameLayout->addWidget(usernameEdit);
    usernameLayout->addWidget(copyUsernameButton);
    detailsLayout->addLayout(usernameLayout);
    
    detailsLayout->addWidget(new QLabel("Password:"));
    QHBoxLayout *passwordLayout = new QHBoxLayout;
    passwordEdit = new QLineEdit;
    passwordEdit->setEchoMode(QLineEdit::Password);
    generatePasswordButton = new QPushButton("Generate");
    generatePasswordButton->setMaximumWidth(80);
    copyPasswordButton = new QPushButton("Copy");
    copyPasswordButton->setMaximumWidth(60);
    passwordLayout->addWidget(passwordEdit);
    passwordLayout->addWidget(generatePasswordButton);
    passwordLayout->addWidget(copyPasswordButton);
    detailsLayout->addLayout(passwordLayout);
    
    showPasswordCheck = new QCheckBox("Show Password");
    detailsLayout->addWidget(showPasswordCheck);
    
    // Password strength indicator (modern design)
    QLabel* strengthLabel = new QLabel("Password Strength:");
    strengthLabel->setStyleSheet("font-weight: bold; color: #333; margin-top: 8px;");
    detailsLayout->addWidget(strengthLabel);
    
    passwordStrengthBar = new QProgressBar;
    passwordStrengthBar->setRange(0, 100);
    passwordStrengthBar->setTextVisible(false);
    passwordStrengthBar->setFixedHeight(8);
    passwordStrengthBar->setStyleSheet(
        "QProgressBar {"
        "    border: none;"
        "    background-color: #e0e0e0;"
        "    border-radius: 4px;"
        "}"
        "QProgressBar::chunk {"
        "    background-color: #ff4444;"
        "    border-radius: 4px;"
        "    margin: 0px;"
        "}"
    );
    detailsLayout->addWidget(passwordStrengthBar);
    
    passwordStrengthLabel = new QLabel("Enter a password to see its strength");
    passwordStrengthLabel->setWordWrap(true);
    passwordStrengthLabel->setStyleSheet(
        "color: #666;"
        "font-size: 12px;"
        "font-weight: 500;"
        "margin-top: 4px;"
        "margin-bottom: 8px;"
    );
    detailsLayout->addWidget(passwordStrengthLabel);
    
    detailsLayout->addWidget(new QLabel("URL:"));
    urlEdit = new QLineEdit;
    detailsLayout->addWidget(urlEdit);
    
    detailsLayout->addWidget(new QLabel("Notes:"));
    notesEdit = new QTextEdit;
    notesEdit->setMaximumHeight(100);
    detailsLayout->addWidget(notesEdit);
    
    // Action buttons
    QHBoxLayout *actionLayout = new QHBoxLayout;
    saveButton = new QPushButton("Save");
    cancelButton = new QPushButton("Cancel");
    actionLayout->addWidget(saveButton);
    actionLayout->addWidget(cancelButton);
    actionLayout->addStretch();
    detailsLayout->addLayout(actionLayout);
    
    rightLayout->addWidget(detailsGroup);
    rightLayout->addStretch();
    
    // Add panels to splitter
    mainSplitter->addWidget(leftPanel);
    mainSplitter->addWidget(rightPanel);
    mainSplitter->setStretchFactor(0, 1);
    mainSplitter->setStretchFactor(1, 2);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->addWidget(mainSplitter);
    
    // Initially disable edit controls and database-dependent features
    saveButton->setEnabled(false);
    cancelButton->setEnabled(false);
    editButton->setEnabled(false);
    deleteButton->setEnabled(false);
    addButton->setEnabled(false);
    searchBox->setEnabled(false);
}

void MainWindow::setupMenuBar() {
    // File menu
    QMenu *fileMenu = menuBar()->addMenu("&File");
    
    newAction = new QAction("&New Database", this);
    newAction->setShortcut(QKeySequence::New);
    newAction->setStatusTip("Create a new password database in the project directory");
    fileMenu->addAction(newAction);
    
    openAction = new QAction("&Open Database...", this);
    openAction->setShortcut(QKeySequence::Open);
    openAction->setStatusTip("Open an existing password database");
    fileMenu->addAction(openAction);
    
    closeAction = new QAction("&Close Database", this);
    closeAction->setShortcut(QKeySequence("Ctrl+W"));
    closeAction->setStatusTip("Close the current database");
    closeAction->setEnabled(false);
    fileMenu->addAction(closeAction);
    
    fileMenu->addSeparator();
    
    changePasswordAction = new QAction("&Change Master Password", this);
    changePasswordAction->setStatusTip("Change the master password for the current database");
    changePasswordAction->setEnabled(false);
    fileMenu->addAction(changePasswordAction);
    
    fileMenu->addSeparator();
    
    settingsAction = new QAction("&Settings...", this);
    settingsAction->setShortcut(QKeySequence::Preferences);
    settingsAction->setStatusTip("Open application settings");
    fileMenu->addAction(settingsAction);
    
    fileMenu->addSeparator();
    
    exitAction = new QAction("E&xit", this);
    exitAction->setShortcut(QKeySequence::Quit);
    exitAction->setStatusTip("Exit the application");
    fileMenu->addAction(exitAction);
    
    // Help menu
    QMenu *helpMenu = menuBar()->addMenu("&Help");
    aboutAction = new QAction("&About", this);
    aboutAction->setStatusTip("About this application");
    helpMenu->addAction(aboutAction);
    
    statusBar()->showMessage("Ready - No database loaded", 0);
}

void MainWindow::connectSignals() {
    // Menu actions
    connect(newAction, &QAction::triggered, this, &MainWindow::newDatabase);
    connect(openAction, &QAction::triggered, this, &MainWindow::openDatabase);
    connect(closeAction, &QAction::triggered, this, &MainWindow::closeDatabase);
    connect(changePasswordAction, &QAction::triggered, this, &MainWindow::changePassword);
    connect(settingsAction, &QAction::triggered, this, &MainWindow::showSettings);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);
    connect(aboutAction, &QAction::triggered, this, &MainWindow::about);
    
    // Button actions
    connect(addButton, &QPushButton::clicked, this, &MainWindow::addEntry);
    connect(editButton, &QPushButton::clicked, this, &MainWindow::editEntry);
    connect(deleteButton, &QPushButton::clicked, this, &MainWindow::deleteEntry);
    connect(saveButton, &QPushButton::clicked, this, &MainWindow::updateEntryDetails);
    connect(cancelButton, &QPushButton::clicked, this, &MainWindow::clearEntryDetails);
    
    connect(generatePasswordButton, &QPushButton::clicked, this, &MainWindow::generatePassword);
    connect(copyUsernameButton, &QPushButton::clicked, this, &MainWindow::copyUsername);
    connect(copyPasswordButton, &QPushButton::clicked, this, &MainWindow::copyPassword);
    
    // Password strength monitoring
    connect(passwordEdit, &QLineEdit::textChanged, this, &MainWindow::onPasswordChanged);
    
    // Other controls
    connect(searchBox, &QLineEdit::textChanged, this, &MainWindow::searchEntries);
    connect(entryList, &QListWidget::itemSelectionChanged, this, &MainWindow::onEntrySelected);
    connect(showPasswordCheck, &QCheckBox::toggled, this, &MainWindow::togglePasswordVisibility);
}

void MainWindow::newDatabase() {
    // Create database in project directory with default name
    QString dataPath = getProjectDataPath();
    QString defaultFileName = dataPath + "/passwords.db";
    
    // Check if default database already exists
    if (QFile::exists(defaultFileName)) {
        int ret = QMessageBox::question(this, "Database Exists", 
                                       "A database already exists in the project directory. Do you want to:\n\n"
                                       "Yes - Replace it with a new database\n"
                                       "No - Choose a different location\n"
                                       "Cancel - Do nothing",
                                       QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);
        
        if (ret == QMessageBox::Cancel) {
            return;
        } else if (ret == QMessageBox::No) {
            // Let user choose location
            QString fileName = QFileDialog::getSaveFileName(this, "Create New Database", 
                                                           dataPath + "/passwords_new.db",
                                                           "Database Files (*.db)");
            if (fileName.isEmpty()) {
                return;
            }
            
            // Check if the selected file already exists
            if (QFile::exists(fileName)) {
                int overwriteRet = QMessageBox::question(this, "File Exists", 
                                                        QString("The file '%1' already exists. Do you want to replace it?")
                                                        .arg(QFileInfo(fileName).fileName()),
                                                        QMessageBox::Yes | QMessageBox::No);
                if (overwriteRet == QMessageBox::No) {
                    return;
                }
                
                // Remove existing file
                if (!QFile::remove(fileName)) {
                    QMessageBox::critical(this, "Error", "Failed to remove existing database file.");
                    return;
                }
                LOG_INFO(QString("Removed existing database file: %1").arg(fileName));
            }
            
            defaultFileName = fileName;
        } else if (ret == QMessageBox::Yes) {
            // Remove existing file so we can create a new one
            if (!QFile::remove(defaultFileName)) {
                QMessageBox::critical(this, "Error", "Failed to remove existing database file.");
                return;
            }
            LOG_INFO(QString("Removed existing database file: %1").arg(defaultFileName));
        }
    }
    
    LOG_INFO(QString("Creating new database at: %1").arg(defaultFileName));
    
    // Create database object first
    currentDatabasePath = defaultFileName;
    database = std::make_unique<PasswordDatabase>(defaultFileName.toStdString());
    
    // Then prompt for password and set it
    if (promptForNewPassword()) {
        refreshEntryList();
        updateUIState(true);
        statusBar()->showMessage(QString("New database created: %1").arg(QFileInfo(defaultFileName).fileName()), 0);
        LOG_INFO("New database created and password set successfully");
    } else {
        // If password setting failed, clean up
        database.reset();
        currentDatabasePath.clear();
        LOG_ERROR("Failed to set password for new database");
        statusBar()->showMessage("Failed to create database", 3000);
    }
}

void MainWindow::openDatabase() {
    QString defaultDir = getProjectDataPath();
    QString fileName = QFileDialog::getOpenFileName(this, "Open Existing Database", 
                                                   defaultDir,
                                                   "Database Files (*.db);;All Files (*)");
    if (!fileName.isEmpty()) {
        LOG_INFO(QString("Opening database: %1").arg(fileName));
        
        // Close current database if any
        if (database) {
            database.reset();
            entryList->clear();
            clearEntryDetails();
        }
        
        currentDatabasePath = fileName;
        database = std::make_unique<PasswordDatabase>(fileName.toStdString());
        
        if (authenticateUser()) {
            refreshEntryList();
            updateUIState(true);
            statusBar()->showMessage(QString("Database opened: %1").arg(QFileInfo(fileName).fileName()), 0);
            LOG_INFO("Database opened and authenticated successfully");
        } else {
            QMessageBox::warning(this, "Authentication Failed", "Invalid password or corrupted database file!");
            database.reset();
            currentDatabasePath.clear();
            statusBar()->showMessage("Failed to open database", 3000);
            LOG_WARNING("Failed to authenticate with database");
        }
    }
}

void MainWindow::closeDatabase() {
    if (!database) {
        QMessageBox::information(this, "No Database", "No database is currently open.");
        return;
    }
    
    int ret = QMessageBox::question(this, "Close Database", 
                                   "Are you sure you want to close the current database?\n\n"
                                   "Any unsaved changes will be lost.",
                                   QMessageBox::Yes | QMessageBox::No);
    
    if (ret == QMessageBox::Yes) {
        LOG_INFO("Closing current database");
        
        database.reset();
        currentDatabasePath.clear();
        entryList->clear();
        clearEntryDetails();
        
        // Update UI state
        updateUIState(false);
        
        statusBar()->showMessage("Database closed - Ready to open or create a database", 0);
        LOG_INFO("Database closed successfully");
    }
}

void MainWindow::changePassword() {
    if (!database) {
        QMessageBox::warning(this, "No Database", "Please open a database first.");
        return;
    }
    
    bool ok;
    QString oldPassword = QInputDialog::getText(this, "Change Password", "Enter current password:", 
                                               QLineEdit::Password, "", &ok);
    if (!ok) return;
    
    QString newPassword = QInputDialog::getText(this, "Change Password", "Enter new password:", 
                                               QLineEdit::Password, "", &ok);
    if (!ok) return;
    
    QString confirmPassword = QInputDialog::getText(this, "Change Password", "Confirm new password:", 
                                                   QLineEdit::Password, "", &ok);
    if (!ok) return;
    
    if (newPassword != confirmPassword) {
        QMessageBox::warning(this, "Password Mismatch", "Passwords do not match!");
        return;
    }
    
    if (database->changeMasterPassword(oldPassword.toStdString(), newPassword.toStdString())) {
        QMessageBox::information(this, "Success", "Password changed successfully!");
    } else {
        QMessageBox::warning(this, "Failed", "Failed to change password. Check your current password.");
    }
}

void MainWindow::addEntry() {
    if (!database) {
        QMessageBox::warning(this, "No Database", "Please open a database first.");
        return;
    }
    
    isEditing = true;
    currentEntryId.clear();
    clearEntryDetails();
    
    titleEdit->setEnabled(true);
    usernameEdit->setEnabled(true);
    passwordEdit->setEnabled(true);
    urlEdit->setEnabled(true);
    notesEdit->setEnabled(true);
    saveButton->setEnabled(true);
    cancelButton->setEnabled(true);
    
    titleEdit->setFocus();
}

void MainWindow::editEntry() {
    if (!database || entryList->currentRow() < 0) {
        LOG_WARNING("Cannot edit entry: no database or no entry selected");
        return;
    }
    
    if (currentEntryId.empty()) {
        LOG_ERROR("Cannot edit entry: currentEntryId is empty");
        QMessageBox::warning(this, "Error", "No entry selected for editing!");
        return;
    }
    
    LOG_INFO(QString("Starting edit mode for entry ID: %1").arg(QString::fromStdString(currentEntryId)));
    
    isEditing = true;
    
    titleEdit->setEnabled(true);
    usernameEdit->setEnabled(true);
    passwordEdit->setEnabled(true);
    urlEdit->setEnabled(true);
    notesEdit->setEnabled(true);
    saveButton->setEnabled(true);
    cancelButton->setEnabled(true);
}

void MainWindow::deleteEntry() {
    if (!database || entryList->currentRow() < 0) {
        return;
    }
    
    int ret = QMessageBox::question(this, "Confirm Delete", 
                                   "Are you sure you want to delete this entry?",
                                   QMessageBox::Yes | QMessageBox::No);
    
    if (ret == QMessageBox::Yes) {
        // Set deletion flag to prevent selection events
        isDeletingEntry = true;
        
        if (database->deleteEntry(currentEntryId)) {
            // Clear selection first to prevent accessing deleted entry
            entryList->clearSelection();
            refreshEntryList();
            clearEntryDetails();
            statusBar()->showMessage("Entry deleted successfully");
        } else {
            QMessageBox::warning(this, "Error", "Failed to delete entry!");
        }
        
        // Clear deletion flag
        isDeletingEntry = false;
    }
}

void MainWindow::searchEntries() {
    if (!database) return;
    
    QString query = searchBox->text();
    entryList->clear();
    
    std::vector<PasswordEntry> entries;
    if (query.isEmpty()) {
        entries = database->getAllEntries();
    } else {
        entries = database->searchEntries(query.toStdString());
    }
    
    for (const auto& entry : entries) {
        QListWidgetItem *item = new QListWidgetItem(QString::fromStdString(entry.title));
        item->setData(Qt::UserRole, QString::fromStdString(entry.id));
        entryList->addItem(item);
    }
}

void MainWindow::onEntrySelected() {
    // Skip selection events if we're in the middle of deleting an entry
    if (isDeletingEntry) {
        LOG_DEBUG("Ignoring entry selection during deletion");
        return;
    }
    
    if (!database || entryList->currentRow() < 0) {
        editButton->setEnabled(false);
        deleteButton->setEnabled(false);
        currentEntryId.clear();
        LOG_INFO("No entry selected or no database");
        return;
    }
    
    editButton->setEnabled(true);
    deleteButton->setEnabled(true);
    
    QListWidgetItem *item = entryList->currentItem();
    if (item) {
        QString idString = item->data(Qt::UserRole).toString();
        currentEntryId = idString.toStdString();
        
        LOG_INFO(QString("Selected entry with ID: '%1' (length: %2)").arg(idString).arg(idString.length()));
        
        if (currentEntryId.empty()) {
            LOG_ERROR("Entry ID is empty! This should not happen.");
            LOG_ERROR(QString("Item text: '%1'").arg(item->text()));
            LOG_ERROR(QString("Item data type: %1").arg(item->data(Qt::UserRole).typeName()));
            return;
        }
        
        PasswordEntry *entry = database->getEntry(currentEntryId);
        if (entry) {
            showEntryDetails(*entry);
            LOG_INFO(QString("Displaying details for entry: %1").arg(QString::fromStdString(entry->title)));
        } else {
            LOG_ERROR(QString("Failed to get entry details for ID: '%1'").arg(QString::fromStdString(currentEntryId)));
            LOG_ERROR("Available entries in database:");
            auto allEntries = database->getAllEntries();
            for (const auto& e : allEntries) {
                LOG_ERROR(QString("  - ID: '%1', Title: '%2'").arg(QString::fromStdString(e.id)).arg(QString::fromStdString(e.title)));
            }
            // Don't refresh the list here - this might be causing the deletion
            // Instead, just clear the details and show an error
            clearEntryDetails();
            statusBar()->showMessage("Error accessing entry. Please try selecting it again.", 3000);
            return;
        }
    } else {
        LOG_ERROR("No current item in entry list");
    }
}

void MainWindow::generatePassword() {
    // Use a single robust password generation method
    std::string password = CryptoUtils::generateSecurePassword(20, true, true, true, true);
    
    passwordEdit->setText(QString::fromStdString(password));
    statusBar()->showMessage("Generated secure password", 2000);
    
    // Automatically trigger strength calculation
    onPasswordChanged();
}

void MainWindow::togglePasswordVisibility() {
    if (showPasswordCheck->isChecked()) {
        passwordEdit->setEchoMode(QLineEdit::Normal);
    } else {
        passwordEdit->setEchoMode(QLineEdit::Password);
    }
}

void MainWindow::copyUsername() {
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(usernameEdit->text());
    statusBar()->showMessage("Username copied to clipboard", 2000);
}

void MainWindow::copyPassword() {
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(passwordEdit->text());
    statusBar()->showMessage("Password copied to clipboard", 2000);
}

void MainWindow::onPasswordChanged() {
    QString password = passwordEdit->text();
    int strength = CryptoUtils::calculatePasswordStrength(password.toStdString());
    
    passwordStrengthBar->setValue(strength);
    
    // Modern color scheme and styling based on strength
    QString color, strengthText, strengthEmoji;
    
    if (strength < 20) {
        color = "#e74c3c"; // Modern red
        strengthText = "Very Weak";
        strengthEmoji = "🔓";
    } else if (strength < 40) {
        color = "#f39c12"; // Modern orange
        strengthText = "Weak";
        strengthEmoji = "⚠️";
    } else if (strength < 60) {
        color = "#f1c40f"; // Modern yellow
        strengthText = "Fair";
        strengthEmoji = "🔶";
    } else if (strength < 80) {
        color = "#27ae60"; // Modern green
        strengthText = "Good";
        strengthEmoji = "✅";
    } else {
        color = "#2ecc71"; // Bright green
        strengthText = "Excellent";
        strengthEmoji = "🔒";
    }
    
    // Apply modern gradient styling
    QString styleSheet = QString(
        "QProgressBar {"
        "    border: none;"
        "    background-color: #f0f0f0;"
        "    border-radius: 4px;"
        "    text-align: center;"
        "}"
        "QProgressBar::chunk {"
        "    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        "        stop:0 %1, stop:1 %2);"
        "    border-radius: 4px;"
        "    margin: 0px;"
        "}"
    ).arg(color, color.replace("#", "#dd")); // Slightly lighter end color
    
    passwordStrengthBar->setStyleSheet(styleSheet);
    
    // Update label with emoji and modern styling
    QString labelText = QString("%1 %2 (%3%)").arg(strengthEmoji, strengthText).arg(strength);
    passwordStrengthLabel->setText(labelText);
    passwordStrengthLabel->setStyleSheet(QString(
        "color: %1;"
        "font-size: 12px;"
        "font-weight: 600;"
        "margin-top: 4px;"
        "margin-bottom: 8px;"
    ).arg(color));
}

void MainWindow::showSettings() {
    SettingsDialog dialog(this, currentDatabasePath);
    
    // Connect the database restored signal
    connect(&dialog, &SettingsDialog::databaseRestored, this, [this]() {
        // Reload the database
        if (database && database->loadFromFile()) {
            refreshEntryList();
            LOG_INFO("Database reloaded successfully after restore");
        } else {
            LOG_ERROR("Failed to reload database after restore");
        }
    });
    
    dialog.exec();
}

void MainWindow::about() {
    QMessageBox::about(this, "About Password Manager", 
                      "Password Manager v1.3.0\n\n"
                      "A secure password manager built with C++ and Qt.\n\n"
                      "Security Features:\n"
                      "• AES-256-CBC encryption with OpenSSL\n"
                      "• PBKDF2 key derivation (100,000 iterations)\n"
                      "• Real-time password strength analysis\n"
                      "• Secure random password generation\n"
                      "• Advanced settings and themes\n\n"
                      "Built with Qt6 and modern C++17");
}

void MainWindow::refreshEntryList() {
    entryList->clear();
    searchBox->clear();
    
    if (!database) return;
    
    auto entries = database->getAllEntries();
    LOG_INFO(QString("Refreshing entry list with %1 entries").arg(entries.size()));
    
    for (const auto& entry : entries) {
        QListWidgetItem *item = new QListWidgetItem(QString::fromStdString(entry.title));
        item->setData(Qt::UserRole, QString::fromStdString(entry.id));
        entryList->addItem(item);
        
        LOG_INFO(QString("Added entry '%1' with ID '%2'").arg(QString::fromStdString(entry.title)).arg(QString::fromStdString(entry.id)));
    }
}

void MainWindow::clearEntryDetails() {
    // Clear the current entry ID to prevent accessing deleted entries
    currentEntryId.clear();
    
    titleEdit->clear();
    usernameEdit->clear();
    passwordEdit->clear();
    urlEdit->clear();
    notesEdit->clear();
    
    // Reset password strength indicator with modern styling
    passwordStrengthBar->setValue(0);
    passwordStrengthLabel->setText("Enter a password to see its strength");
    passwordStrengthLabel->setStyleSheet(
        "color: #666;"
        "font-size: 12px;"
        "font-weight: 500;"
        "margin-top: 4px;"
        "margin-bottom: 8px;"
    );
    passwordStrengthBar->setStyleSheet(
        "QProgressBar {"
        "    border: none;"
        "    background-color: #e0e0e0;"
        "    border-radius: 4px;"
        "}"
        "QProgressBar::chunk {"
        "    background-color: #ff4444;"
        "    border-radius: 4px;"
        "    margin: 0px;"
        "}"
    );
    
    titleEdit->setEnabled(false);
    usernameEdit->setEnabled(false);
    passwordEdit->setEnabled(false);
    urlEdit->setEnabled(false);
    notesEdit->setEnabled(false);
    saveButton->setEnabled(false);
    cancelButton->setEnabled(false);
    
    isEditing = false;
    currentEntryId.clear();
}

void MainWindow::showEntryDetails(const PasswordEntry& entry) {
    if (isEditing) return;
    
    titleEdit->setText(QString::fromStdString(entry.title));
    usernameEdit->setText(QString::fromStdString(entry.username));
    passwordEdit->setText(QString::fromStdString(entry.password));
    urlEdit->setText(QString::fromStdString(entry.url));
    notesEdit->setPlainText(QString::fromStdString(entry.notes));
    
    // Update password strength indicator
    onPasswordChanged();
}

void MainWindow::updateEntryDetails() {
    if (!database) return;
    
    if (titleEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Title cannot be empty!");
        return;
    }
    
    bool success = false;
    
    if (currentEntryId.empty()) {
        // Adding new entry
        LOG_INFO("Creating new password entry");
        
        PasswordEntry entry;
        entry.title = titleEdit->text().toStdString();
        entry.username = usernameEdit->text().toStdString();
        entry.password = passwordEdit->text().toStdString();
        entry.url = urlEdit->text().toStdString();
        entry.notes = notesEdit->toPlainText().toStdString();
        entry.generateId();  // Generate a unique ID for the new entry
        
        LOG_INFO(QString("Generated ID for new entry: %1").arg(QString::fromStdString(entry.id)));
        
        success = database->addEntry(entry);
        
        if (success) {
            LOG_INFO("New entry created successfully");
        } else {
            LOG_ERROR("Failed to create new entry");
        }
    } else {
        // Updating existing entry
        LOG_INFO(QString("Updating existing entry with ID: %1").arg(QString::fromStdString(currentEntryId)));
        
        PasswordEntry* existingEntry = database->getEntry(currentEntryId);
        if (!existingEntry) {
            LOG_ERROR("Failed to find existing entry for update");
            QMessageBox::warning(this, "Error", "Could not find the entry to update!");
            return;
        }
        
        // Preserve original data and update only the fields that changed
        PasswordEntry updatedEntry = *existingEntry;  // Copy the original entry
        updatedEntry.title = titleEdit->text().toStdString();
        updatedEntry.username = usernameEdit->text().toStdString();
        updatedEntry.password = passwordEdit->text().toStdString();
        updatedEntry.url = urlEdit->text().toStdString();
        updatedEntry.notes = notesEdit->toPlainText().toStdString();
        // Keep original ID and creation time, modified time will be updated in database
        
        success = database->updateEntry(currentEntryId, updatedEntry);
        
        if (success) {
            LOG_INFO("Entry updated successfully");
        } else {
            LOG_ERROR("Failed to update entry");
        }
    }
    
    if (success) {
        refreshEntryList();
        clearEntryDetails();
        statusBar()->showMessage("Entry saved successfully");
    } else {
        QMessageBox::warning(this, "Error", "Failed to save entry!");
    }
}

bool MainWindow::authenticateUser() {
    if (!database) {
        LOG_ERROR("Database object is null in authenticateUser");
        return false;
    }
    
    try {
        bool ok;
        QString password = QInputDialog::getText(this, "Authentication", "Enter master password:", 
                                               QLineEdit::Password, "", &ok);
        if (!ok) {
            LOG_INFO("User cancelled authentication");
            return false;
        }
        
        LOG_INFO("Attempting to authenticate user");
        bool result = database->authenticate(password.toStdString());
        
        if (result) {
            LOG_INFO("User authentication successful");
        } else {
            LOG_WARNING("User authentication failed - incorrect password");
        }
        
        return result;
    } catch (const std::exception& e) {
        LOG_ERROR(QString("Exception in authenticateUser: %1").arg(e.what()));
        QMessageBox::critical(this, "Error", "An error occurred during authentication.");
        return false;
    } catch (...) {
        LOG_ERROR("Unknown exception in authenticateUser");
        QMessageBox::critical(this, "Error", "An unknown error occurred during authentication.");
        return false;
    }
}

bool MainWindow::promptForNewPassword() {
    try {
        bool ok;
        QString password = QInputDialog::getText(this, "New Database", "Enter master password:", 
                                               QLineEdit::Password, "", &ok);
        if (!ok) return false;
        
        QString confirmPassword = QInputDialog::getText(this, "New Database", "Confirm master password:", 
                                                       QLineEdit::Password, "", &ok);
        if (!ok) return false;
        
        if (password != confirmPassword) {
            QMessageBox::warning(this, "Password Mismatch", "Passwords do not match!");
            return false;
        }
        
        if (password.length() < 6) {
            QMessageBox::warning(this, "Weak Password", "Password must be at least 6 characters long!");
            return false;
        }
        
        LOG_INFO("Setting new master password for database");
        
        if (!database) {
            LOG_ERROR("Database object is null when trying to set master password");
            return false;
        }
        
        bool result = database->setMasterPassword(password.toStdString());
        if (result) {
            LOG_INFO("Master password set successfully");
        } else {
            LOG_ERROR("Failed to set master password");
        }
        
        return result;
    } catch (const std::exception& e) {
        LOG_ERROR(QString("Exception in promptForNewPassword: %1").arg(e.what()));
        QMessageBox::critical(this, "Error", "An error occurred while setting the password.");
        return false;
    } catch (...) {
        LOG_ERROR("Unknown exception in promptForNewPassword");
        QMessageBox::critical(this, "Error", "An unknown error occurred while setting the password.");
        return false;
    }
}

QString MainWindow::getProjectDataPath() const {
    // For system-wide installation, use user's home directory
    // For local development, use project directory
    
    QString executablePath = QCoreApplication::applicationDirPath();
    
    // Check if we're running from system installation
    if (executablePath.startsWith("/usr/") || executablePath.startsWith("/opt/")) {
        // System installation - use user's home directory
        QString homeDir = QDir::homePath();
        QString dataPath = homeDir + "/.local/share/PasswordManager";
        
        // Ensure the directory exists
        QDir().mkpath(dataPath);
        
        LOG_INFO(QString("Using system installation data path: %1").arg(dataPath));
        return dataPath;
    }
    
    // Development/local installation - try to find project directory
    QDir projectDir(executablePath);
    
    // If we're in build/bin, go up two levels to project root
    if (projectDir.dirName() == "bin" && projectDir.cdUp() && projectDir.dirName() == "build") {
        projectDir.cdUp(); // Now we're at project root
    }
    // If we're directly in build directory, go up one level
    else if (projectDir.dirName() == "build") {
        projectDir.cdUp(); // Now we're at project root
    }
    // If data directory exists relative to executable
    else if (QDir(executablePath + "/data").exists()) {
        projectDir = QDir(executablePath);
    }
    // Try to find project data directory in nearby locations
    else {
        QStringList searchPaths = {
            executablePath + "/data",
            executablePath + "/../data",
            executablePath + "/../../data",
            executablePath + "/../../../data"
        };
        
        for (const QString& path : searchPaths) {
            QDir testDir(path);
            if (testDir.exists()) {
                LOG_INFO(QString("Found project data directory: %1").arg(QDir(path).absolutePath()));
                return QDir(path).absolutePath();
            }
        }
        
        // Fallback: create data directory relative to executable
        QString fallbackPath = executablePath + "/data";
        QDir().mkpath(fallbackPath);
        LOG_WARNING(QString("Using fallback data path: %1").arg(fallbackPath));
        return fallbackPath;
    }
    
    QString dataPath = projectDir.absolutePath() + "/data";
    
    // Ensure the data directory exists
    QDir().mkpath(dataPath);
    
    LOG_INFO(QString("Using project data path: %1").arg(dataPath));
    return dataPath;
}

void MainWindow::updateUIState(bool databaseOpen) {
    // Update menu actions
    closeAction->setEnabled(databaseOpen);
    changePasswordAction->setEnabled(databaseOpen);
    
    // Update buttons
    addButton->setEnabled(databaseOpen);
    editButton->setEnabled(databaseOpen && entryList->currentRow() >= 0);
    deleteButton->setEnabled(databaseOpen && entryList->currentRow() >= 0);
    
    // Update search
    searchBox->setEnabled(databaseOpen);
    
    if (!databaseOpen) {
        // Clear everything when no database is open
        entryList->clear();
        clearEntryDetails();
    }
}
