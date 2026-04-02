#pragma once

#include <string>
#include <vector>
#include <chrono>
#include "types.hpp"

struct ScanState {
    std::string target;
    std::vector<int> ports;
    std::vector<int> scannedPorts;
    std::vector<ScanResult> results;
    int threads;
    float timeout;
    ScanType scanType;
    bool detectVersion;
    std::chrono::steady_clock::time_point startTime;
};

class StateManager {
public:
    static bool saveState(const ScanState& state, const std::string& filename);
    static bool loadState(const std::string& filename, ScanState& state);
    static bool hasState(const std::string& filename);
    static bool clearState(const std::string& filename);
    
private:
    static std::string scanTypeToString(ScanType type);
    static ScanType stringToScanType(const std::string& s);
};
