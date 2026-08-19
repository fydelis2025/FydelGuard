#ifndef FIREWALLMANAGER_H
#define FIREWALLMANAGER_H

#include <string>
#include <vector>

struct FirewallRule {
    int number;
    std::string direction;  // "ALLOW IN", "DENY OUT", etc.
    std::string port;
    std::string protocol;   // tcp, udp
    std::string from;       // IP ou "Anywhere"
};

class FirewallManager {
public:
    FirewallManager();
    ~FirewallManager();

    bool enable();
    bool disable();
    bool isEnabled();
    bool addAllowRule(const std::string& port, const std::string& protocol = "tcp",
                      const std::string& from = "");
    bool deleteRule(int number);
    std::vector<FirewallRule> listRules();

private:
    std::string execCmd(const std::string& cmd);
};

#endif
