#include "QuarantineManager.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <atomic>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {
// Contador monotônico para garantir nomes únicos mesmo com timestamp colidindo
// (mesmo segundo) e mesmo stem de arquivo.
std::atomic<uint64_t> g_quarantineCounter{0};
}

QuarantineManager::QuarantineManager() {}

QuarantineManager::~QuarantineManager() {
    std::lock_guard<std::mutex> lock(m_dbMutex);
    if (m_db) sqlite3_close(m_db);
}

bool QuarantineManager::initialize(const std::string& dbPath) {
    std::error_code ec;

    fs::create_directories(m_quarantineDir, ec);
    if (ec) {
        std::cerr << "[FydelGuard] Erro ao criar diretório de quarentena: " << ec.message() << std::endl;
        return false;
    }
    // Restringe o diretório de quarentena: só o dono (root) pode ler/escrever/entrar.
    ::chmod(m_quarantineDir.c_str(), S_IRWXU);

    fs::create_directories(fs::path(dbPath).parent_path(), ec);
    if (ec) {
        std::cerr << "[FydelGuard] Erro ao criar diretório do banco: " << ec.message() << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(m_dbMutex);
    int rc = sqlite3_open(dbPath.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao abrir banco: "
                  << (m_db ? sqlite3_errmsg(m_db) : "falha desconhecida") << std::endl;
        return false;
    }
    return createTables();
}

bool QuarantineManager::createTables() {
    // Assume m_dbMutex já travado pelo chamador (initialize)
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
        std::cerr << "[FydelGuard] Erro SQL: " << (err ? err : "desconhecido") << std::endl;
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool QuarantineManager::quarantineFile(const std::string& originalPath, const std::string& threatName) {
    if (!fs::exists(originalPath)) return false;

    auto ts = currentTimestamp();
    auto stem = fs::path(originalPath).stem().string();
    auto ext = fs::path(originalPath).extension().string();

    // Sufixo com contador monotônico + pid evita colisão de nomes quando
    // vários arquivos com o mesmo stem são colocados em quarentena no mesmo segundo.
    uint64_t counter = g_quarantineCounter.fetch_add(1, std::memory_order_relaxed);
    std::ostringstream nameBuilder;
    nameBuilder << stem << "_" << ts << "_" << ::getpid() << "_" << counter << ext;
    auto quarFile = m_quarantineDir + nameBuilder.str();

    // rename() com std::error_code: não lança exceção, então o fallback
    // de cross-device (EXDEV) realmente é alcançado quando necessário.
    std::error_code ec;
    fs::rename(originalPath, quarFile, ec);

    if (ec) {
        // Provavelmente cross-device (EXDEV) ou outra falha — tenta copiar e remover.
        std::error_code copyEc;
        fs::copy_file(originalPath, quarFile, fs::copy_options::overwrite_existing, copyEc);
        if (copyEc) {
            std::cerr << "[FydelGuard] Erro ao colocar em quarentena (copy): "
                      << copyEc.message() << std::endl;
            return false;
        }
        std::error_code removeEc;
        fs::remove(originalPath, removeEc);
        if (removeEc) {
            std::cerr << "[FydelGuard] Aviso: arquivo copiado para quarentena, mas não foi "
                         "possível remover o original: " << removeEc.message() << std::endl;
            // Não é fatal para o registro em quarentena, mas o arquivo original
            // malicioso ainda existe no lugar — vale alertar o usuário na UI.
        }
    }

    // Restringe permissões do arquivo em quarentena: ninguém executa/lê por engano.
    ::chmod(quarFile.c_str(), S_IRUSR | S_IWUSR);

    std::lock_guard<std::mutex> lock(m_dbMutex);
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO quarantine (original_path, quarantined_path, threat_name, date) "
                      "VALUES (?, ?, ?, ?);";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao preparar INSERT: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, originalPath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, quarFile.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, threatName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, ts.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[FydelGuard] Erro ao gravar registro de quarentena: "
                  << sqlite3_errmsg(m_db) << std::endl;
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool QuarantineManager::findByIdLocked(int id, QuarantineEntry& out) {
    // Assume m_dbMutex já travado pelo chamador
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, original_path, quarantined_path, threat_name, date "
                      "FROM quarantine WHERE id = ?;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao preparar SELECT por id: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    sqlite3_bind_int(stmt, 1, id);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out.id              = sqlite3_column_int(stmt, 0);
        out.originalPath    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        out.quarantinedPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        out.threatName      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        out.date            = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

bool QuarantineManager::restoreFile(int id) {
    std::lock_guard<std::mutex> lock(m_dbMutex);

    QuarantineEntry e;
    if (!findByIdLocked(id, e)) return false;

    if (!fs::exists(e.quarantinedPath)) {
        std::cerr << "[FydelGuard] Arquivo em quarentena não encontrado no disco: "
                  << e.quarantinedPath << std::endl;
        return false;
    }

    // Evita sobrescrever um arquivo que já exista no caminho original
    // (ex.: o usuário recriou o arquivo depois que o original foi para quarentena).
    if (fs::exists(e.originalPath)) {
        std::cerr << "[FydelGuard] Já existe um arquivo em " << e.originalPath
                  << " — restauração abortada para evitar sobrescrita." << std::endl;
        return false;
    }

    std::error_code ec;
    fs::rename(e.quarantinedPath, e.originalPath, ec);
    if (ec) {
        // Fallback cross-device, igual ao quarantineFile
        std::error_code copyEc;
        fs::copy_file(e.quarantinedPath, e.originalPath, copyEc);
        if (copyEc) {
            std::cerr << "[FydelGuard] Erro ao restaurar: " << copyEc.message() << std::endl;
            return false;
        }
        fs::remove(e.quarantinedPath, ec);
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "DELETE FROM quarantine WHERE id = ?;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao preparar DELETE: " << sqlite3_errmsg(m_db) << std::endl;
        // Arquivo já foi restaurado no disco; o registro no banco ficará
        // órfão, mas isso é preferível a perder o arquivo restaurado.
        return true;
    }
    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[FydelGuard] Aviso: falha ao remover registro do banco após restaurar: "
                  << sqlite3_errmsg(m_db) << std::endl;
    }
    sqlite3_finalize(stmt);
    return true;
}

bool QuarantineManager::deleteFile(int id) {
    std::lock_guard<std::mutex> lock(m_dbMutex);

    QuarantineEntry e;
    if (!findByIdLocked(id, e)) return false;

    if (fs::exists(e.quarantinedPath)) {
        std::error_code ec;
        fs::remove(e.quarantinedPath, ec);
        if (ec) {
            std::cerr << "[FydelGuard] Erro ao remover arquivo em quarentena: " << ec.message() << std::endl;
            return false;
        }
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "DELETE FROM quarantine WHERE id = ?;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao preparar DELETE: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }
    sqlite3_bind_int(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[FydelGuard] Erro ao remover registro do banco: " << sqlite3_errmsg(m_db) << std::endl;
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<QuarantineEntry> QuarantineManager::listAll() {
    std::lock_guard<std::mutex> lock(m_dbMutex);

    std::vector<QuarantineEntry> entries;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, original_path, quarantined_path, threat_name, date "
                      "FROM quarantine ORDER BY id DESC;";
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[FydelGuard] Erro ao preparar SELECT: " << sqlite3_errmsg(m_db) << std::endl;
        return entries;
    }

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
