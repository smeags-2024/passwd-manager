#include "logger.h"
#include <QtCore/QDir>
#include <iostream>

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::initialize(const QString& logFilePath) {
    logPath = logFilePath;
    
    // Ensure the directory exists
    QDir logDir = QFileInfo(logFilePath).absoluteDir();
    if (!logDir.exists()) {
        logDir.mkpath(".");
    }
    
    logFile = std::make_unique<std::ofstream>(logFilePath.toStdString(), std::ios::app);
    
    if (logFile->is_open()) {
        info("=== Password Manager Session Started ===");
    } else {
        std::cerr << "Failed to open log file: " << logFilePath.toStdString() << std::endl;
    }
}

Logger::~Logger() {
    if (logFile && logFile->is_open()) {
        info("=== Password Manager Session Ended ===");
        logFile->close();
    }
}

void Logger::log(LogLevel level, const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    QString logEntry = QString("[%1] [%2] %3")
                      .arg(timestamp)
                      .arg(levelToString(level))
                      .arg(message);
    
    // Always write to file if available
    if (logFile && logFile->is_open()) {
        *logFile << logEntry.toStdString() << std::endl;
        logFile->flush();
    }
    
    // Only output to console for warnings and errors (to reduce clutter)
    if (level >= WARNING) {
        std::cout << logEntry.toStdString() << std::endl;
    }
}

void Logger::setLogLevel(LogLevel level) {
    currentLogLevel = level;
}

QString Logger::levelToString(LogLevel level) const {
    switch (level) {
        case DEBUG: return "DEBUG";
        case INFO: return "INFO";
        case WARNING: return "WARNING";
        case ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}
