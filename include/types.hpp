#pragma once

#include <string>
#include <vector>

enum class ScanType {
    CONNECT,
    SYN,
    FIN,
    XMAS,
    NULL_SCAN,
    UDP
};

struct ScanResult {
    int port;
    std::string protocol;
    std::string service;
    std::string version;
    std::string description;
    std::vector<std::string> cves;
};

struct ScanConfig {
    std::string target;
    std::vector<int> ports;
    int threads;
    float timeout;
    ScanType scanType;
    bool detectVersion;
};
