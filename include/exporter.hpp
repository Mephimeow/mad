#pragma once

#include <string>
#include <vector>
#include "types.hpp"

enum class ExportFormat {
    JSON,
    XML,
    CSV,
    TEXT
};

class ResultExporter {
public:
    static bool exportResults(const std::vector<ScanResult>& results, 
                              const std::string& filename,
                              ExportFormat format);
    
private:
    static std::string resultsToJson(const std::vector<ScanResult>& results);
    static std::string resultsToXml(const std::vector<ScanResult>& results);
    static std::string resultsToCsv(const std::vector<ScanResult>& results);
    static std::string resultsToText(const std::vector<ScanResult>& results);
    
    static std::string escapeJson(const std::string& s);
    static std::string escapeXml(const std::string& s);
};
