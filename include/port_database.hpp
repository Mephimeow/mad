#pragma once

#include <string>
#include <map>
#include <utility>
#include <vector>

struct PortInfo {
    std::string service;
    std::string description;
    std::vector<std::string> cves;
};

class PortDatabase {
public:
    static const PortInfo& getInfo(int port);
    static std::string getServiceName(int port);
    static bool isKnownPort(int port);
    static std::vector<std::string> getCves(int port);
};
