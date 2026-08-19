#include "QuarantineManager.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>
namespace fs = std::filesystem;

QuarantineManager::QuarantineManager() {}
QuarantineManager::~QuarantineManager() {
    if (m_db) sqlite3_close(m_db);
}

bool QuarantineManager::initialize(const std::string& dbPath) {
    fs::create_directories(m_quarantineDir);
    fs::create_directories(fs::path(dbPath).parent_path());

    int rc = sqlite3_open(dbPath.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao abrir banco: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    return createTables();
}

bool QuarantineManager::createTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            quarantined_path TEXT NOT NULL,
            threat_name TEXT DEFAULT 'Unknown',
            date TEXT NOT NULL
        );
    )";
    char* err = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro SQL: " << err << std::endl;
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool QuarantineManager::quarantineFile(const std::string& originalPath, const std::string& threatName) {
    try {
        if (!fs::exists(originalPath)) return false;

        auto ts = currentTimestamp();
        auto stem = fs::path(originalPath).stem().string();
        auto ext = fs::path(originalPath).extension().string();
        auto quarFile = m_quarantineDir + stem + "_" + ts + ext;

        // Move para quarentena
        fs::rename(originalPath, quarFile);

        // Tenta copiar se rename falhar (cross-device)
        if (!fs::exists(quarFile)) {
            fs::copy(originalPath, quarFile);
            fs::remove(originalPath);
        }

        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO quarantine (original_path, quarantined_path, threat_name, date) "
                          "VALUES (?, ?, ?, ?);";
        sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, originalPath.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, quarFile.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, threatName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, ts.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;

    } catch (const fs::filesystem_error& e) {
        std::cerr << "[FydelGuard] Erro em quarentena: " << e.what() << std::endl;
        return false;
    }
}

bool QuarantineManager::restoreFile(int id) {
    auto entries = listAll();
    for (auto& e : entries) {
        if (e.id == id) {
            try {
                if (!fs::exists(e.quarantinedPath)) return false;
                fs::rename(e.quarantinedPath, e.originalPath);

                sqlite3_stmt* stmt;
                const char* sql = "DELETE FROM quarantine WHERE id = ?;";
                sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
                sqlite3_bind_int(stmt, 1, id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                return true;
            } catch (const fs::filesystem_error& ex) {
                std::cerr << "[FydelGuard] Erro ao restaurar: " << ex.what() << std::endl;
                return false;
            }
        }
    }
    return false;
}

bool QuarantineManager::deleteFile(int id) {
    auto entries = listAll();
    for (auto& e : entries) {
        if (e.id == id) {
            try {
                if (fs::exists(e.quarantinedPath))
                    fs::remove(e.quarantinedPath);

                sqlite3_stmt* stmt;
                const char* sql = "DELETE FROM quarantine WHERE id = ?;";
                sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
                sqlite3_bind_int(stmt, 1, id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                return true;
            } catch (...) { return false; }
        }
    }
    return false;
}

std::vector<QuarantineEntry> QuarantineManager::listAll() {
    std::vector<QuarantineEntry> entries;
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, original_path, quarantined_path, threat_name, date "
                      "FROM quarantine ORDER BY id DESC;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return entries;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QuarantineEntry e;
        e.id              = sqlite3_column_int(stmt, 0);
        e.originalPath    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        e.quarantinedPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        e.threatName      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        e.date            = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        entries.push_back(e);
    }
    sqlite3_finalize(stmt);
    return entries;
}

std::string QuarantineManager::currentTimestamp() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return oss.str();
}
