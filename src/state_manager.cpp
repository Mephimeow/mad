#include "state_manager.hpp"
#include "exporter.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>

bool StateManager::saveState(const ScanState& state, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# Scan State File\n";
    file << "target: " << state.target << "\n";
    
    file << "ports: ";
    for (size_t i = 0; i < state.ports.size(); ++i) {
        if (i > 0) file << ",";
        file << state.ports[i];
    }
    file << "\n";
    
    file << "scanned: ";
    for (size_t i = 0; i < state.scannedPorts.size(); ++i) {
        if (i > 0) file << ",";
        file << state.scannedPorts[i];
    }
    file << "\n";
    
    file << "threads: " << state.threads << "\n";
    file << "timeout: " << state.timeout << "\n";
    file << "scan_type: " << scanTypeToString(state.scanType) << "\n";
    file << "detect_version: " << (state.detectVersion ? "true" : "false") << "\n";
    file << "start_time: " << std::chrono::duration_cast<std::chrono::seconds>(
        state.startTime.time_since_epoch()).count() << "\n";
    
    if (!state.results.empty()) {
        file << "\n[RESULTS]\n";
        std::string jsonResults = ResultExporter::resultsToJson(state.results);
        file << jsonResults;
    }
    
    file.close();
    return true;
}

bool StateManager::loadState(const std::string& filename, ScanState& state) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    bool inResults = false;
    std::string resultsJson;
    std::string line;
    
    while (std::getline(file, line)) {
        if (line == "[RESULTS]") {
            inResults = true;
            continue;
        }
        
        if (inResults) {
            resultsJson += line + "\n";
            continue;
        }
        
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        
        key = key.erase(key.find_last_not_of(" \t\r\n") + 1);
        value = value.erase(0, value.find_first_not_of(" \t"));
        
        if (key == "target") {
            state.target = value;
        } else if (key == "ports") {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ',')) {
                state.ports.push_back(std::stoi(token));
            }
        } else if (key == "scanned") {
            std::istringstream iss(value);
            std::string token;
            while (std::getline(iss, token, ',')) {
                state.scannedPorts.push_back(std::stoi(token));
            }
        } else if (key == "threads") {
            state.threads = std::stoi(value);
        } else if (key == "timeout") {
            state.timeout = std::stof(value);
        } else if (key == "scan_type") {
            state.scanType = stringToScanType(value);
        } else if (key == "detect_version") {
            state.detectVersion = (value == "true");
        } else if (key == "start_time") {
            long long ts = std::stoll(value);
            state.startTime = std::chrono::steady_clock::time_point(
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::seconds(ts)));
        }
    }
    
    file.close();
    
    if (!resultsJson.empty()) {
        return ResultExporter::parseResultsFromJson(resultsJson, state.results);
    }
    
    return true;
}

bool StateManager::hasState(const std::string& filename) {
    std::ifstream file(filename);
    return file.is_open();
}

bool StateManager::clearState(const std::string& filename) {
    return std::remove(filename.c_str()) == 0;
}

std::string StateManager::scanTypeToString(ScanType type) {
    switch (type) {
        case ScanType::SYN: return "syn";
        case ScanType::FIN: return "fin";
        case ScanType::XMAS: return "xmas";
        case ScanType::NULL_SCAN: return "null";
        case ScanType::UDP: return "udp";
        default: return "connect";
    }
}

ScanType StateManager::stringToScanType(const std::string& s) {
    if (s == "syn") return ScanType::SYN;
    if (s == "fin") return ScanType::FIN;
    if (s == "xmas") return ScanType::XMAS;
    if (s == "null") return ScanType::NULL_SCAN;
    if (s == "udp") return ScanType::UDP;
    return ScanType::CONNECT;
}
