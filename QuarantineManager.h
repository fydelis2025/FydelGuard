#ifndef QUARANTINEMANAGER_H
#define QUARANTINEMANAGER_H

#include <string>
#include <vector>
#include <sqlite3.h>

struct QuarantineEntry {
    int id;
    std::string originalPath;
    std::string quarantinedPath;
    std::string threatName;
    std::string date;
};

class QuarantineManager {
public:
    QuarantineManager();
    ~QuarantineManager();

    bool initialize(const std::string& dbPath = "/var/lib/fydelguard/quarantine.db");
    bool quarantineFile(const std::string& originalPath, const std::string& threatName);
    bool restoreFile(int id);
    bool deleteFile(int id);
    std::vector<QuarantineEntry> listAll();

private:
    sqlite3* m_db = nullptr;
    std::string m_quarantineDir = "/var/lib/fydelguard/quarantine/";
    bool createTables();
    std::string currentTimestamp();
};

#endif
