#include <QtWidgets/QApplication>
#include <QtWidgets/QStyleFactory>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include "main_window.h"
#include "logger.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    // Suppress Qt debug output for cleaner console
    qputenv("QT_LOGGING_RULES", "*.debug=false;qt.qpa.xcb.debug=false");
    
    // Set application properties
    app.setApplicationName("Password Manager");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("SecureApps");
    app.setOrganizationDomain("secureapps.com");
    
    // Create project data directory relative to executable
    QString executablePath = QCoreApplication::applicationDirPath();
    QString dataDir;
    
    // Check if we're running from system installation
    if (executablePath.startsWith("/usr/") || executablePath.startsWith("/opt/")) {
        // System installation - use user's home directory
        QString homeDir = QDir::homePath();
        dataDir = homeDir + "/.local/share/PasswordManager";
    } else {
        // Development/local installation
        QDir projectDir(executablePath);
        
        // Navigate to project root and ensure data directory exists
        if (projectDir.dirName() == "bin" && projectDir.cdUp() && projectDir.dirName() == "build") {
            projectDir.cdUp(); // Now we're at project root
        } else if (projectDir.dirName() == "build") {
            projectDir.cdUp(); // Now we're at project root
        }
        
        dataDir = projectDir.absolutePath() + "/data";
    }
    
    QDir().mkpath(dataDir);
    
    // Initialize logging
    QString logFile = dataDir + "/password_manager.log";
    Logger::getInstance().initialize(logFile);
    LOG_INFO("Application starting...");
    
    // Use system default style and theme to avoid palette issues
    // Comment out custom styling to use system defaults
    // app.setStyle(QStyleFactory::create("Fusion"));
    
    // No custom stylesheet - use system default
    // app.setStyleSheet(...);
    
    // Create and show main window
    MainWindow window;
    window.show();
    
    return app.exec();
}
