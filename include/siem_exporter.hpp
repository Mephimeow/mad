#pragma once

#include <string>
#include <vector>
#include <chrono>
#include "types.hpp"
#include "exporter.hpp"

enum class SiemFormat {
    SYSLOG,
    CEF,
    JSON
};

class SiemExporter {
public:
    static bool sendToSyslog(const std::vector<ScanResult>& results, const std::string& host);
    static std::string formatCef(const ScanResult& result, const std::string& deviceHost);
    static std::string formatSyslog(const ScanResult& result, const std::string& deviceHost);
    static bool sendToSiem(const std::vector<ScanResult>& results, 
                          const std::string& siemHost, 
                          int siemPort,
                          SiemFormat format);
    
private:
    static std::string getCurrentTimestamp();
};
