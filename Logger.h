#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>

enum class LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };

class Logger {
public:
    static Logger& instance();
    void setLogFile(const std::string& path);
    void log(LogLevel level, const std::string& message);

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    Logger();
    ~Logger();
    std::string levelToString(LogLevel level);
    std::string formatTimestamp();

    std::ofstream m_logFile;
    std::mutex m_mutex;
    std::string m_filePath;
};

#endif // LOGGER_H
