#include "config.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>

bool Config::loadFromFile(const std::string& filename, ScanConfig& config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        
        std::string key = trim(line.substr(0, colon));
        std::string value = trim(line.substr(colon + 1));
        
        if (key == "target") {
            config.target = value;
        } else if (key == "ports") {
            config.ports = parsePortsFromConfig(value);
        } else if (key == "threads") {
            config.threads = std::stoi(value);
        } else if (key == "timeout") {
            config.timeout = std::stof(value);
        } else if (key == "scan_type") {
            config.scanType = parseScanTypeFromConfig(value);
        } else if (key == "detect_version") {
            config.detectVersion = (value == "true" || value == "1");
        }
    }
    
    file.close();
    return true;
}

bool Config::saveToFile(const std::string& filename, const ScanConfig& config) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# Port Scanner Configuration\n\n";
    file << "target: " << config.target << "\n";
    
    file << "ports: ";
    for (size_t i = 0; i < config.ports.size(); ++i) {
        if (i > 0) file << ",";
        file << config.ports[i];
    }
    file << "\n";
    
    file << "threads: " << config.threads << "\n";
    file << "timeout: " << config.timeout << "\n";
    
    std::string scanTypeStr;
    switch (config.scanType) {
        case ScanType::SYN: scanTypeStr = "syn"; break;
        case ScanType::FIN: scanTypeStr = "fin"; break;
        case ScanType::XMAS: scanTypeStr = "xmas"; break;
        case ScanType::NULL_SCAN: scanTypeStr = "null"; break;
        case ScanType::UDP: scanTypeStr = "udp"; break;
        default: scanTypeStr = "connect";
    }
    file << "scan_type: " << scanTypeStr << "\n";
    file << "detect_version: " << (config.detectVersion ? "true" : "false") << "\n";
    
    file.close();
    return true;
}

std::string Config::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<int> Config::parsePortsFromConfig(const std::string& portStr) {
    std::vector<int> ports;
    
    if (portStr.find(',') != std::string::npos) {
        std::istringstream iss(portStr);
        std::string token;
        while (std::getline(iss, token, ',')) {
            int port = std::stoi(trim(token));
            if (port >= 1 && port <= 65535) {
                ports.push_back(port);
            }
        }
    } else if (portStr.find('-') != std::string::npos) {
        size_t dash = portStr.find('-');
        int start = std::stoi(trim(portStr.substr(0, dash)));
        int end = std::stoi(trim(portStr.substr(dash + 1)));
        
        if (start >= 1 && end <= 65535 && start <= end) {
            for (int p = start; p <= end; ++p) {
                ports.push_back(p);
            }
        }
    } else {
        int port = std::stoi(portStr);
        if (port >= 1 && port <= 65535) {
            ports.push_back(port);
        }
    }
    
    std::sort(ports.begin(), ports.end());
    return ports;
}

ScanType Config::parseScanTypeFromConfig(const std::string& type) {
    if (type == "syn") return ScanType::SYN;
    if (type == "fin") return ScanType::FIN;
    if (type == "xmas") return ScanType::XMAS;
    if (type == "null") return ScanType::NULL_SCAN;
    if (type == "udp") return ScanType::UDP;
    return ScanType::CONNECT;
}
