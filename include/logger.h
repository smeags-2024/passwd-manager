#ifndef LOGGER_H
#define LOGGER_H

#include <QString>
#include <QDateTime>
#include <fstream>
#include <memory>

class Logger {
public:
    enum LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3
    };

    static Logger& getInstance();
    void initialize(const QString& logFilePath);
    void log(LogLevel level, const QString& message);
    void setLogLevel(LogLevel level);

    // Convenience methods
    void debug(const QString& message) { log(DEBUG, message); }
    void info(const QString& message) { log(INFO, message); }
    void warning(const QString& message) { log(WARNING, message); }
    void error(const QString& message) { log(ERROR, message); }

private:
    Logger() = default;
    ~Logger();
    
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::unique_ptr<std::ofstream> logFile;
    LogLevel currentLogLevel = INFO;
    QString logPath;
    
    QString levelToString(LogLevel level) const;
};

// Convenience macros
#define LOG_DEBUG(msg) Logger::getInstance().debug(msg)
#define LOG_INFO(msg) Logger::getInstance().info(msg)
#define LOG_WARNING(msg) Logger::getInstance().warning(msg)
#define LOG_ERROR(msg) Logger::getInstance().error(msg)

#endif // LOGGER_H
