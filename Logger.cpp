#include "Logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() = default;
Logger::~Logger() { if (m_logFile.is_open()) m_logFile.close(); }

void Logger::setLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_logFile.is_open()) m_logFile.close();
    m_filePath = path;
    m_logFile.open(path, std::ios::app);
}

std::string Logger::formatTimestamp() {
    auto t = std::time(nullptr);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch(level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string entry = "[" + formatTimestamp() + "] [" + levelToString(level) + "] " + message;
    std::cout << entry << "\n";
    if (m_logFile.is_open()) {
        m_logFile << entry << "\n";
        m_logFile.flush();
    }
}
