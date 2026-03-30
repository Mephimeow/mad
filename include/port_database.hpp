#pragma once

#include <string>
#include <map>
#include <utility>

struct PortInfo {
    std::string service;
    std::string description;
};

class PortDatabase {
public:
    static const PortInfo& getInfo(int port);
    static std::string getServiceName(int port);
    static bool isKnownPort(int port);
};
