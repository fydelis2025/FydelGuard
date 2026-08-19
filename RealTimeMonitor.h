#ifndef REALTIMEMONITOR_H
#define REALTIMEMONITOR_H
#include "Scanner.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <string>

class RealTimeMonitor {
public:
    explicit RealTimeMonitor(Scanner& scanner);
    ~RealTimeMonitor();

    bool start(const std::string& mountPoint = "/");
    void stop();
    bool isRunning() const { return m_running; }

    using ThreatCallback = std::function<void(const std::string& path, const std::string& virusName)>;

    // Thread-safe: pode ser chamado antes ou depois de start().
    void setThreatCallback(ThreatCallback cb);

private:
    void monitorLoop(const std::string& mountPoint);

    // Chama m_threatCb de forma thread-safe (copia o std::function sob lock
    // antes de invocar, para não segurar o mutex durante a execução do callback).
    void invokeThreatCallback(const std::string& path, const std::string& virusName);

    Scanner& m_scanner;
    std::thread m_thread;
    std::atomic<bool> m_running{false};

    ThreatCallback m_threatCb;
    std::mutex m_cbMutex; // protege m_threatCb (set na thread principal, uso na thread do monitor)
};
#endif
