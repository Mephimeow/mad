#include "siem_exporter.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

std::string SiemExporter::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string SiemExporter::formatSyslog(const ScanResult& result, const std::string& deviceHost) {
    std::ostringstream ss;
    ss << "<134>" << getCurrentTimestamp() << " " << deviceHost << " scanner: ";
    ss << "port_detected port=" << result.port << " protocol=" << result.protocol;
    ss << " service=" << result.service;
    if (!result.version.empty()) ss << " version=\"" << result.version << "\"";
    if (!result.cves.empty()) {
        ss << " cves=";
        for (size_t i = 0; i < result.cves.size(); ++i) {
            if (i > 0) ss << ",";
            ss << result.cves[i];
        }
    }
    return ss.str();
}

std::string SiemExporter::formatCef(const ScanResult& result, const std::string& deviceHost) {
    std::ostringstream ss;
    ss << "CEF:0|PortScanner|1.0|10000|Port Scan|0|";
    ss << "src=" << deviceHost << " ";
    ss << "dst=" << deviceHost << " ";
    ss << "spt=" << result.port << " ";
    ss << "dpt=" << result.port << " ";
    ss << "proto=" << result.protocol << " ";
    ss << "cn1=" << result.port << " ";
    ss << "cs1=" << result.service << " ";
    if (!result.version.empty()) ss << "cs2=\"" << result.version << "\" ";
    ss << "cn2=1";
    return ss.str();
}

bool SiemExporter::sendToSyslog(const std::vector<ScanResult>& results, const std::string& host) {
    for (const auto& result : results) {
        std::string msg = formatSyslog(result, host);
        std::cout << msg << std::endl;
    }
    return true;
}

bool SiemExporter::sendToSiem(const std::vector<ScanResult>& results, 
                              const std::string& siemHost, 
                              int siemPort,
                              SiemFormat format) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    
    struct hostent* server = gethostbyname(siemHost.c_str());
    if (server == NULL) {
        close(sock);
        return false;
    }
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    memcpy(&serverAddr.sin_addr.s_addr, server->h_addr, server->h_length);
    serverAddr.sin_port = htons(siemPort);
    
    for (const auto& result : results) {
        std::string msg;
        if (format == SiemFormat::SYSLOG) {
            msg = formatSyslog(result, siemHost);
        } else if (format == SiemFormat::CEF) {
            msg = formatCef(result, siemHost);
        } else {
            msg = ResultExporter::resultsToJson(results);
        }
        
        sendto(sock, msg.c_str(), msg.length(), 0, 
               (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    }
    
    close(sock);
    return true;
}
