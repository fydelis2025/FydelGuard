#ifndef REALTIMEMONITOR_H
#define REALTIMEMONITOR_H

#include "Scanner.h"
#include <thread>
#include <atomic>
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
    void setThreatCallback(ThreatCallback cb) { m_threatCb = cb; }

private:
    void monitorLoop(const std::string& mountPoint);

    Scanner& m_scanner;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    ThreatCallback m_threatCb;
};

#endif
