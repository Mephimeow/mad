#pragma once

#include <string>
#include <vector>
#include "types.hpp"

class Config {
public:
    static bool loadFromFile(const std::string& filename, ScanConfig& config);
    static bool saveToFile(const std::string& filename, const ScanConfig& config);
    static std::vector<int> parsePortsFromConfig(const std::string& portStr);
    
private:
    static std::string trim(const std::string& s);
    static ScanType parseScanTypeFromConfig(const std::string& type);
};
