#include "ScanWorker.h"
#include <filesystem>
#include <iostream>
namespace fs = std::filesystem;

ScanWorker::ScanWorker(Scanner& scanner, unsigned int numThreads) : m_scanner(scanner) {
    for (unsigned int i = 0; i < numThreads; ++i)
        m_threads.emplace_back(&ScanWorker::workerLoop, this, i);
}

ScanWorker::~ScanWorker() { stop(); }

void ScanWorker::enqueueScanFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push(path);
    m_cv.notify_one();
}

void ScanWorker::enqueueScanDir(const std::string& dirPath, bool recursive) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push("__DIR__:" + dirPath + (recursive ? ":1" : ":0"));
    m_cv.notify_one();
}

void ScanWorker::clearQueue() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::queue<std::string> empty;
    std::swap(m_queue, empty);
}

void ScanWorker::stop() {
    m_running = false;
    m_cv.notify_all();
    for (auto& t : m_threads)
        if (t.joinable()) t.join();
    m_threads.clear();
}

void ScanWorker::workerLoop(int id) {
    while (m_running) {
        std::string task;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return !m_queue.empty() || !m_running; });
            if (!m_running) break;
            if (m_queue.empty()) continue;
            task = m_queue.front();
            m_queue.pop();
        }

        if (task.rfind("__DIR__:", 0) == 0) {
            auto rest = task.substr(8);
            bool rec = (rest.size() >= 2 && rest.back() == '1');
            std::string dir = rec ? rest.substr(0, rest.size() - 2) : rest;
            scanDirectory(dir, rec);
        } else {
            auto report = m_scanner.scanFile(task);
            m_filesScanned++;
            if (m_reportCb) m_reportCb(report);
            if (m_progressCb) m_progressCb(m_filesScanned, m_totalFiles);
        }
    }
}

void ScanWorker::scanDirectory(const std::string& dirPath, bool recursive) {
    try {
        int total = 0;

        // Passada 1: Contagem de arquivos de forma segura para ambos os tipos
        if (recursive) {
            fs::recursive_directory_iterator it(dirPath, fs::directory_options::skip_permission_denied);
            for (const auto& entry : it) {
                if (entry.is_regular_file()) total++;
            }
        } else {
            fs::directory_iterator it(dirPath);
            for (const auto& entry : it) {
                if (entry.is_regular_file()) total++;
            }
        }
        m_totalFiles += total;

        // Passada 2: Enfileiramento dos arquivos
        if (recursive) {
            fs::recursive_directory_iterator it(dirPath, fs::directory_options::skip_permission_denied);
            for (const auto& entry : it) {
                if (!m_running) break;
                if (entry.is_regular_file())
                    enqueueScanFile(entry.path().string());
            }
        } else {
            fs::directory_iterator it(dirPath);
            for (const auto& entry : it) {
                if (!m_running) break;
                if (entry.is_regular_file())
                    enqueueScanFile(entry.path().string());
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "[FydelGuard] Erro no diretório: " << e.what() << std::endl;
    }
}
