#ifndef UPDATER_H
#define UPDATER_H

#include <string>
#include <functional>

class Updater {
public:
    Updater();
    ~Updater();

    bool updateClamAVSignatures();
    bool updateApplication();  // placeholder para auto-update

    void setUpdateCallback(std::function<void(const std::string&)> cb) { m_callback = cb; }

private:
    std::function<void(const std::string&)> m_callback;
    std::string execCmd(const std::string& cmd);
};

#endif
