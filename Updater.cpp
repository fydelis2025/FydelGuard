#include "Updater.h"
#include <cstdio>
#include <memory>
#include <array>
#include <iostream>

Updater::Updater() {}
Updater::~Updater() {}

std::string Updater::execCmd(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "[ERRO]";
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        result += buffer.data();
    pclose(pipe);
    return result;
}

bool Updater::updateClamAVSignatures() {
    if (m_callback) m_callback("[FydelGuard] 🔄 Atualizando banco ClamAV...\n");

    // Para o daemon freshclam se estiver rodando
    execCmd("systemctl stop clamav-freshclam 2>/dev/null || true");

    // Executa freshclam manualmente
    std::string output = execCmd("freshclam --stdout 2>&1");
    if (m_callback) m_callback(output);

    // Reinicia o daemon
    execCmd("systemctl start clamav-freshclam 2>/dev/null || true");

    return output.find("OK") != std::string::npos ||
           output.find("Database updated") != std::string::npos;
}

bool Updater::updateApplication() {
    if (m_callback) m_callback("[FydelGuard] 🔄 Verificando atualizações...\n");
    std::string output = execCmd("apt update 2>&1 | tail -3");
    if (m_callback) m_callback(output);
    return true;
}
