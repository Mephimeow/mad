#include "exporter.hpp"
#include "port_database.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cmath>

bool ResultExporter::exportResults(const std::vector<ScanResult>& results,
                                   const std::string& filename,
                                   ExportFormat format) {
    std::string content;
    
    switch (format) {
        case ExportFormat::JSON:
            content = resultsToJson(results);
            break;
        case ExportFormat::XML:
            content = resultsToXml(results);
            break;
        case ExportFormat::CSV:
            content = resultsToCsv(results);
            break;
        case ExportFormat::TEXT:
            content = resultsToText(results);
            break;
        default:
            content = resultsToText(results);
    }
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    file.close();
    return true;
}

std::string ResultExporter::escapeJson(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

std::string ResultExporter::escapeXml(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c;
        }
    }
    return result;
}

std::string ResultExporter::resultsToJson(const std::vector<ScanResult>& results) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"scan_time\": \"" << std::time(nullptr) << "\",\n";
    ss << "  \"results\": [\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        ss << "    {\n";
        ss << "      \"port\": " << r.port << ",\n";
        ss << "      \"protocol\": \"" << escapeJson(r.protocol) << "\",\n";
        ss << "      \"service\": \"" << escapeJson(r.service) << "\",\n";
        ss << "      \"version\": \"" << escapeJson(r.version) << "\",\n";
        ss << "      \"description\": \"" << escapeJson(r.description) << "\"\n";
        ss << "    }";
        if (i < results.size() - 1) ss << ",";
        ss << "\n";
    }
    
    ss << "  ]\n";
    ss << "}\n";
    return ss.str();
}

std::string ResultExporter::resultsToXml(const std::vector<ScanResult>& results) {
    std::ostringstream ss;
    ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ss << "<scan_results>\n";
    ss << "  <scan_time>" << std::time(nullptr) << "</scan_time>\n";
    
    for (const auto& r : results) {
        ss << "  <port>\n";
        ss << "    <number>" << r.port << "</number>\n";
        ss << "    <protocol>" << escapeXml(r.protocol) << "</protocol>\n";
        ss << "    <service>" << escapeXml(r.service) << "</service>\n";
        ss << "    <version>" << escapeXml(r.version) << "</version>\n";
        ss << "    <description>" << escapeXml(r.description) << "</description>\n";
        ss << "  </port>\n";
    }
    
    ss << "</scan_results>\n";
    return ss.str();
}

std::string ResultExporter::resultsToCsv(const std::vector<ScanResult>& results) {
    std::ostringstream ss;
    ss << "port,protocol,service,version,description\n";
    
    for (const auto& r : results) {
        ss << r.port << ",";
        ss << "\"" << r.protocol << "\",";
        ss << "\"" << r.service << "\",";
        ss << "\"" << r.version << "\",";
        ss << "\"" << r.description << "\"\n";
    }
    
    return ss.str();
}

std::string ResultExporter::resultsToText(const std::vector<ScanResult>& results) {
    std::ostringstream ss;
    ss << "Port Scan Results\n";
    ss << "==================\n\n";
    
    for (const auto& r : results) {
        ss << "Port: " << r.port << "\n";
        ss << "Protocol: " << r.protocol << "\n";
        ss << "Service: " << r.service << "\n";
        if (!r.version.empty()) ss << "Version: " << r.version << "\n";
        if (!r.description.empty()) ss << "Description: " << r.description << "\n";
        ss << "\n";
    }
    
    return ss.str();
}
