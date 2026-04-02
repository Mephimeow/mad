#pragma once

#include <string>
#include <atomic>
#include <mutex>
#include <vector>
#include <functional>
#include "types.hpp"

class PortScanner {
public:
    PortScanner(const std::string& target, const std::vector<int>& ports,int threads, float timeout, ScanType scanType, bool detectVersion);
    std::vector<ScanResult> scan();
    void setStateCallback(std::function<void(const std::vector<ScanResult>&)> callback);
    
private:
    void worker(std::atomic<int>& portIndex, std::vector<ScanResult>& results);
    bool scanPort(int port);
    bool sendTcpProbe(int port);
    bool sendTcpProbeFallback(int port);
    bool sendUdpProbe(int port);
    std::string grabBanner(int port);
    std::string getServiceInfo(int port) const;

    std::string target_;
    std::vector<int> ports_;
    int threads_;
    float timeout_;
    ScanType scanType_;
    bool detectVersion_;
    std::mutex printMutex_;
    std::mutex resultsMutex_;
    std::atomic<int> openCount_;
    std::function<void(const std::vector<ScanResult>&)> stateCallback_;
};
