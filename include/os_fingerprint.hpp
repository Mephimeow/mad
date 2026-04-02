#pragma once

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "types.hpp"

struct OsMatch {
    std::string os;
    std::string version;
    float confidence;
    std::vector<int> openPorts;
    std::vector<int> closedPorts;
    std::map<std::string, std::string> tcpFlags;
};

class OsFingerprint {
public:
    static OsMatch fingerprint(const std::string& target, const std::vector<int>& ports);
    static std::string getOsFromTcpResponse(const std::string& target, int port);
    static std::string analyzeUdpPorts(const std::string& target, const std::vector<int>& ports);
    
private:
    static std::map<std::string, OsMatch> getOsSignatures();
    static float calculateMatch(const OsMatch& signature, const std::vector<int>& openPorts, const std::vector<int>& closedPorts);
};
