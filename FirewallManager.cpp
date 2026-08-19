#include "FirewallManager.h"
#include <cstdio>
#include <memory>
#include <array>
#include <iostream>
#include <sstream>
#include <regex>
#include <algorithm>

FirewallManager::FirewallManager() {}
FirewallManager::~FirewallManager() {}

std::string FirewallManager::execCmd(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "[ERRO]";
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        result += buffer.data();
    pclose(pipe);
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

bool FirewallManager::enable() {
    execCmd("ufw --force enable 2>/dev/null");
    return true;
}

bool FirewallManager::disable() {
    execCmd("ufw --force disable 2>/dev/null");
    return true;
}

bool FirewallManager::isEnabled() {
    std::string out = execCmd("ufw status 2>/dev/null");
    return out.find("Status: active") != std::string::npos;
}

bool FirewallManager::addAllowRule(const std::string& port,
                                    const std::string& protocol,
                                    const std::string& from) {
    std::string cmd = "ufw ";
    if (from.empty())
        cmd += "allow " + port + "/" + protocol;
    else
        cmd += "allow from " + from + " to any port " + port + " proto " + protocol;
    cmd += " 2>/dev/null";
    execCmd(cmd);
    return true;
}

bool FirewallManager::deleteRule(int number) {
    execCmd("ufw --force delete " + std::to_string(number) + " 2>/dev/null");
    return true;
}

std::vector<FirewallRule> FirewallManager::listRules() {
    std::vector<FirewallRule> rules;
    std::string out = execCmd("ufw status numbered 2>/dev/null");

    std::istringstream stream(out);
    std::string line;

    // Pula cabeçalho até "---"
    while (std::getline(stream, line)) {
        if (line.find("---") != std::string::npos) break;
    }

    std::regex ruleRegex(R"(\[\s*(\d+)\]\s+(\S+)\s+(\S+\s+\S+)\s+(.+))");
    std::smatch match;

    while (std::getline(stream, line)) {
        if (line.find("---") != std::string::npos) break;
        line = std::regex_replace(line, std::regex(R"(\s+)"), " ");

        if (std::regex_search(line, match, ruleRegex) && match.size() >= 5) {
            FirewallRule r;
            r.number    = std::stoi(match[1].str());
            r.port      = match[2].str();
            r.direction = match[3].str();
            r.from      = match[4].str();

            auto slashPos = r.port.find('/');
            r.protocol = (slashPos != std::string::npos) ? r.port.substr(slashPos + 1) : "any";
            if (slashPos != std::string::npos)
                r.port = r.port.substr(0, slashPos);

            rules.push_back(r);
        }
    }
    return rules;
}
