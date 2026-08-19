#include "RealTimeMonitor.h"
#include <fcntl.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <chrono>
#include <thread>
#include <climits>  // PATH_MAX

RealTimeMonitor::RealTimeMonitor(Scanner& scanner) : m_scanner(scanner) {}

RealTimeMonitor::~RealTimeMonitor() { stop(); }

bool RealTimeMonitor::start(const std::string& mountPoint) {
    if (m_running) return false;
    m_running = true;
    m_thread = std::thread(&RealTimeMonitor::monitorLoop, this, mountPoint);
    return true;
}

void RealTimeMonitor::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
}

void RealTimeMonitor::monitorLoop(const std::string& mountPoint) {
    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                                O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0) {
        std::cerr << "fanotify_init falhou (rode como root): " << strerror(errno) << std::endl;
        m_running = false;
        return;
    }

    // Monitora o sistema de arquivos inteiro no ponto de montagem
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                      FAN_CLOSE_WRITE | FAN_OPEN_PERM,
                      AT_FDCWD, mountPoint.c_str()) < 0) {
        std::cerr << "fanotify_mark falhou: " << strerror(errno) << std::endl;
        close(fan_fd);
        m_running = false;
        return;
    }

    std::cout << "🛡️ RealTimeMonitor ativo em: " << mountPoint << std::endl;

    char buf[4096];
    while (m_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fan_fd, &rfds);
        struct timeval tv = {1, 0}; // timeout 1s para checar m_running

        int ret = select(fan_fd + 1, &rfds, nullptr, nullptr, &tv);
        if (ret < 0) break;
        if (ret == 0) continue; // timeout

        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN) continue;
            break;
        }

        auto* metadata = (fanotify_event_metadata*)buf;
        while (len > 0 && metadata->fd >= 0) {
            if (metadata->mask & FAN_CLOSE_WRITE) {
                // Arquivo foi fechado após escrita — escaneie
                char procPath[64];
                char filePath[PATH_MAX] = {0};
                snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", metadata->fd);
                ssize_t pathLen = readlink(procPath, filePath, sizeof(filePath) - 1);
                if (pathLen > 0) {
                    filePath[pathLen] = '\0';
                    auto report = m_scanner.scanFile(filePath);
                    if (report.result == ScanResult::Infected && m_threatCb) {
                        m_threatCb(filePath, report.virusName);
                    }
                }
            }

            if (metadata->mask & FAN_OPEN_PERM) {
                // Permissão de abertura — podemos bloquear se infectado
                char procPath[64];
                char filePath[PATH_MAX] = {0};
                snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", metadata->fd);
                readlink(procPath, filePath, sizeof(filePath) - 1);

                auto report = m_scanner.scanFile(filePath);
                struct fanotify_response response;
                response.fd = metadata->fd;

                if (report.result == ScanResult::Infected) {
                    response.response = FAN_DENY; // BLOQUEIA O ACESSO!
                    if (m_threatCb) m_threatCb(filePath, report.virusName);
                } else {
                    response.response = FAN_ALLOW;
                }
                write(fan_fd, &response, sizeof(response));
            }

            // Avança para o próximo evento
            len -= metadata->event_len;
            metadata = (fanotify_event_metadata*)((char*)metadata + metadata->event_len);
        }

        // Fecha os fds dos eventos após processar
        // (Na prática, cada metadata->fd precisa ser fechado após uso)
    }

    close(fan_fd);
}
