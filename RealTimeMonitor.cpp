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

void RealTimeMonitor::setThreatCallback(ThreatCallback cb) {
    std::lock_guard<std::mutex> lock(m_cbMutex);
    m_threatCb = std::move(cb);
}

void RealTimeMonitor::invokeThreatCallback(const std::string& path, const std::string& virusName) {
    ThreatCallback cbCopy;
    {
        std::lock_guard<std::mutex> lock(m_cbMutex);
        cbCopy = m_threatCb;
    }
    if (cbCopy) cbCopy(path, virusName);
}

// Resolve o caminho real do arquivo a partir do fd do evento fanotify.
// Retorna false se não foi possível resolver (ex.: fd inválido, arquivo removido).
static bool resolveEventPath(int eventFd, char* outPath, size_t outLen) {
    char procPath[64];
    snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", eventFd);
    ssize_t pathLen = readlink(procPath, outPath, outLen - 1);
    if (pathLen <= 0) return false;
    outPath[pathLen] = '\0';
    return true;
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
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue; // timeout

        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN) continue;
            break;
        }

        auto* metadata = (fanotify_event_metadata*)buf;
        while (len > 0 && metadata->fd >= 0) {
            char filePath[PATH_MAX] = {0};
            bool havePath = resolveEventPath(metadata->fd, filePath, sizeof(filePath));

            if (metadata->mask & FAN_CLOSE_WRITE) {
                // Arquivo foi fechado após escrita — escaneie
                if (havePath) {
                    auto report = m_scanner.scanFile(filePath);
                    if (report.result == ScanResult::Infected) {
                        invokeThreatCallback(filePath, report.virusName);
                    }
                } else {
                    std::cerr << "RealTimeMonitor: não foi possível resolver path (FAN_CLOSE_WRITE), fd="
                              << metadata->fd << std::endl;
                }
            }

            if (metadata->mask & FAN_OPEN_PERM) {
                // Permissão de abertura — podemos bloquear se infectado.
                // Se não conseguirmos resolver o path, liberamos por padrão
                // (fail-open) para não travar o sistema em caso de erro,
                // mas registramos o ocorrido para auditoria.
                struct fanotify_response response;
                response.fd = metadata->fd;

                if (havePath) {
                    auto report = m_scanner.scanFile(filePath);
                    if (report.result == ScanResult::Infected) {
                        response.response = FAN_DENY; // BLOQUEIA O ACESSO!
                        invokeThreatCallback(filePath, report.virusName);
                    } else {
                        response.response = FAN_ALLOW;
                    }
                } else {
                    response.response = FAN_ALLOW;
                    std::cerr << "RealTimeMonitor: não foi possível resolver path (FAN_OPEN_PERM), fd="
                              << metadata->fd << " — liberando por padrão" << std::endl;
                }

                if (write(fan_fd, &response, sizeof(response)) < 0) {
                    std::cerr << "RealTimeMonitor: falha ao responder fanotify: "
                              << strerror(errno) << std::endl;
                }
            }

            // Fecha o fd do evento — obrigatório, senão vaza um fd por evento
            close(metadata->fd);

            // Avança para o próximo evento
            len -= metadata->event_len;
            metadata = (fanotify_event_metadata*)((char*)metadata + metadata->event_len);
        }
    }

    close(fan_fd);
}
