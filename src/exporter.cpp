#include "exporter.hpp"
#include "port_database.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cmath>
#include <regex>

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

std::string ResultExporter::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool ResultExporter::parseResultsFromJson(const std::string& json, std::vector<ScanResult>& results) {
    results.clear();
    
    std::regex portRegex("\"port\":\\s*(\\d+)");
    std::regex protoRegex("\"protocol\":\\s*\"([^\"]*)\"");
    std::regex servRegex("\"service\":\\s*\"([^\"]*)\"");
    std::regex versRegex("\"version\":\\s*\"([^\"]*)\"");
    std::regex descRegex("\"description\":\\s*\"([^\"]*)\"");
    
    std::sregex_iterator it(json.begin(), json.end(), portRegex);
    std::sregex_iterator end;
    
    for (; it != end; ++it) {
        std::match_results<std::string::const_iterator> match = *it;
        ScanResult result;
        result.port = std::stoi(match[1].str());
        
        std::string::const_iterator searchStart = match[0].second;
        
        std::smatch protoMatch;
        if (std::regex_search(searchStart, json.end(), protoMatch, protoRegex)) {
            result.protocol = protoMatch[1].str();
            searchStart = protoMatch[0].second;
        }
        
        std::smatch servMatch;
        if (std::regex_search(searchStart, json.end(), servMatch, servRegex)) {
            result.service = servMatch[1].str();
            searchStart = servMatch[0].second;
        }
        
        std::smatch versMatch;
        if (std::regex_search(searchStart, json.end(), versMatch, versRegex)) {
            result.version = versMatch[1].str();
        }
        
        std::smatch descMatch;
        if (std::regex_search(searchStart, json.end(), descMatch, descRegex)) {
            result.description = descMatch[1].str();
        }
        
        results.push_back(result);
    }
    
    return !results.empty();
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
