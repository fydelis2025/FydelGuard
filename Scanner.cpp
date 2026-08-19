#include "Scanner.h"
#include <iostream>
#include <cstring>

Scanner::Scanner() {}

Scanner::~Scanner() { shutdown(); }

bool Scanner::initialize(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    cl_error_t ret = cl_init(CL_INIT_DEFAULT);
    if (ret != CL_SUCCESS) {
        std::cerr << "[FydelGuard] cl_init falhou: " << cl_strerror(ret) << std::endl;
        return false;
    }

    // Na versão 1.4, cl_engine_new() retorna diretamente o ponteiro (ou nullptr em caso de falha)
    m_engine = cl_engine_new();
    if (!m_engine) {
        std::cerr << "[FydelGuard] cl_engine_new falhou ao alocar o engine." << std::endl;
        return false;
    }

    // Tenta carregar base de assinaturas de múltiplos locais
    std::vector<std::string> dbPaths = {
        dbPath,
        "/var/lib/clamav",
        "/usr/share/clamav",
        "./clamav_db"
    };

    bool loaded = false;
    unsigned int sigs = 0;
    for (const auto& path : dbPaths) {
        ret = cl_load(path.c_str(), m_engine, &sigs, CL_DB_STDOPT);
        if (ret == CL_SUCCESS) {
            loaded = true;
            std::cout << "[FydelGuard] Banco carregado de: " << path << std::endl;
            break;
        }
    }

    if (!loaded) {
        std::cerr << "[FydelGuard] Nenhum banco de assinaturas encontrado!" << std::endl;
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    ret = cl_engine_compile(m_engine);
    if (ret != CL_SUCCESS) {
        std::cerr << "[FydelGuard] cl_engine_compile falhou: " << cl_strerror(ret) << std::endl;
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    m_signatureCount = sigs;
    std::cout << "[FydelGuard] ✔ Engine carregado: " << m_signatureCount << " assinaturas" << std::endl;
    return true;
}

void Scanner::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_engine) {
        cl_engine_free(m_engine);
        m_engine = nullptr;
        std::cout << "[FydelGuard] Engine liberado." << std::endl;
    }
}

ScanReport Scanner::scanFile(const std::string& path) {
    ScanReport report;
    report.filePath  = path;
    report.result    = ScanResult::Error;
    report.virusName = "";
    report.scanTimeMs = 0;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_engine) return report;

    auto start = std::chrono::high_resolution_clock::now();

    const char* virname = nullptr;
    struct cl_scan_options options;
    std::memset(&options, 0, sizeof(options));
    
    // Ajustado para as flags suportadas pelo ClamAV 1.4+
    options.general = CL_SCAN_GENERAL_ALLMATCHES;

    cl_error_t ret = cl_scanfile(path.c_str(), &virname, nullptr, m_engine, &options);

    auto end = std::chrono::high_resolution_clock::now();
    report.scanTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    switch (ret) {
        case CL_CLEAN:  report.result = ScanResult::Clean;   break;
        case CL_VIRUS:  report.result = ScanResult::Infected;
                        report.virusName = virname ? virname : "Desconhecido"; break;
        default:        report.result = ScanResult::Error;   break;
    }

    return report;
}
