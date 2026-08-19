#ifndef SCANWORKER_H
#define SCANWORKER_H

#include "Scanner.h"
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <vector>

class ScanWorker {
public:
    explicit ScanWorker(Scanner& scanner, unsigned int numThreads = 4);
    ~ScanWorker();

    void enqueueScanFile(const std::string& path);
    void enqueueScanDir(const std::string& dirPath, bool recursive);
    void clearQueue();
    void stop();
    bool isRunning() const { return m_running; }

    void setReportCallback(std::function<void(const ScanReport&)> cb)  { m_reportCb = cb; }
    void setFinishedCallback(std::function<void()> cb)                 { m_finishedCb = cb; }
    void setProgressCallback(std::function<void(int, int)> cb)         { m_progressCb = cb; } // atual, total

private:
    void workerLoop(int id);
    void scanDirectory(const std::string& dirPath, bool recursive);

    Scanner& m_scanner;
    std::queue<std::string> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<std::thread> m_threads;
    std::atomic<bool> m_running{true};
    std::atomic<int> m_filesScanned{0};
    std::atomic<int> m_totalFiles{0};

    std::function<void(const ScanReport&)> m_reportCb;
    std::function<void()> m_finishedCb;
    std::function<void(int, int)> m_progressCb;
};

#endif
