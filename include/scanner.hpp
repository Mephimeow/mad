#pragma once

#include <string>
#include <atomic>
#include <mutex>

class PortScanner {
public:
    PortScanner(const std::string& target, int startPort, int endPort,
                int threads, float timeout);

    void scan();

private:
    void worker(std::atomic<int>& portCounter);
    void scanPort(int port);
    std::string getServiceName(int port) const;

    std::string target_;
    int startPort_;
    int endPort_;
    int threads_;
    float timeout_;
    std::mutex printMutex_;
    std::atomic<int> openCount_;
};

void validateIP(const std::string& ipStr);
void parsePorts(const std::string& portStr, int& start, int& end);
void printUsage(const char* prog);
