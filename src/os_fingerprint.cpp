#include "os_fingerprint.hpp"

#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>

std::map<std::string, OsMatch> OsFingerprint::getOsSignatures() {
    static std::map<std::string, OsMatch> signatures = {
        {"linux", {"Linux", "2.4/2.6/3.x", 0.8, {22, 80, 443}, {}, {{"window", "5840"}}}},
        {"windows", {"Windows", "XP/7/10/Server", 0.7, {135, 139, 445, 3389}, {}, {{"window", "65535"}}}},
        {"freebsd", {"FreeBSD", "9/10/11", 0.75, {22, 80}, {}, {{"window", "65535"}}}},
        {"macos", {"macOS", "10.x/11.x", 0.7, {22, 445}, {}, {{"window", "65535"}}}},
        {"solaris", {"Solaris", "10/11", 0.65, {22, 80, 111}, {}, {{"window", "8760"}}}},
        {"network", {"Network Device", "Router/Switch", 0.6, {22, 23, 80, 443}, {80, 161}, {{"window", "4128"}}}},
    };
    return signatures;
}

float OsFingerprint::calculateMatch(const OsMatch& signature, const std::vector<int>& openPorts, const std::vector<int>& closedPorts) {
    int matchCount = 0;
    int totalExpected = signature.openPorts.size() + signature.closedPorts.size();
    
    for (int port : signature.openPorts) {
        if (std::find(openPorts.begin(), openPorts.end(), port) != openPorts.end()) {
            matchCount++;
        }
    }
    
    for (int port : signature.closedPorts) {
        if (std::find(closedPorts.begin(), closedPorts.end(), port) != closedPorts.end()) {
            matchCount++;
        }
    }
    
    return (totalExpected > 0) ? (float)matchCount / totalExpected : 0.0f;
}

OsMatch OsFingerprint::fingerprint(const std::string& target, const std::vector<int>& ports) {
    OsMatch result;
    result.os = "Unknown";
    result.confidence = 0.0f;
    
    std::vector<int> openPorts;
    std::vector<int> closedPorts;
    
    for (int port : ports) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            openPorts.push_back(port);
        } else {
            closedPorts.push_back(port);
        }
        close(sock);
    }
    
    auto signatures = getOsSignatures();
    float bestMatch = 0.0f;
    std::string bestOs;
    
    for (const auto& pair : signatures) {
        float match = calculateMatch(pair.second, openPorts, closedPorts);
        if (match > bestMatch) {
            bestMatch = match;
            bestOs = pair.first;
        }
    }
    
    if (bestMatch > 0.3) {
        result = signatures[bestOs];
        result.confidence = bestMatch;
    }
    
    return result;
}

std::string OsFingerprint::getOsFromTcpResponse(const std::string& target, int port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        return "Unknown";
    }
    
    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    
    close(sock);
    return "Unknown";
}

std::string OsFingerprint::analyzeUdpPorts(const std::string& target, const std::vector<int>& ports) {
    std::ostringstream ss;
    
    for (int port : ports) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) continue;
        
        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        char packet[4] = {0};
        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr));
        
        char buffer[4096];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                               (struct sockaddr*)&src_addr, &addr_len);
        
        if (len > 0) {
            ss << port << " (open) ";
        }
        
        close(sock);
    }
    
    return ss.str();
}
