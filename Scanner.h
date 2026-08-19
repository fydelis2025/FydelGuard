#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <mutex>
#include <clamav.h>
#include <chrono>

enum class ScanResult { Clean, Infected, Error };

struct ScanReport {
    std::string filePath;
    ScanResult  result;
    std::string virusName;
    long        scanTimeMs;
};

class Scanner {
public:
     Scanner();
    ~Scanner();
    bool initialize(const std::string& dbPath = "/var/lib/clamav");
    void shutdown();
    ScanReport scanFile(const std::string& path);
    bool isInitialized() const { return m_engine != nullptr; }
    unsigned int signatureCount() const { return m_signatureCount; }

private:
    cl_engine* m_engine = nullptr;
    std::mutex m_mutex;
    unsigned int m_signatureCount = 0;
};

#endif
