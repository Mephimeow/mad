#include "nse_engine.hpp"

#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>

std::map<std::string, std::function<std::vector<ScriptResult>(const ScanResult&)>>& ScriptRegistry::getScripts() {
    static std::map<std::string, std::function<std::vector<ScriptResult>(const ScanResult&)>> scripts;
    return scripts;
}

void ScriptRegistry::registerScript(const std::string& name, 
                                    std::function<std::vector<ScriptResult>(const ScanResult&)> func) {
    getScripts()[name] = func;
}

std::vector<ScriptResult> ScriptRegistry::runScripts(const std::string& port, const ScanResult& result) {
    std::vector<ScriptResult> allResults;
    
    for (auto& pair : getScripts()) {
        auto scriptResults = pair.second(result);
        allResults.insert(allResults.end(), scriptResults.begin(), scriptResults.end());
    }
    
    return allResults;
}

std::vector<std::string> ScriptRegistry::getAvailableScripts() {
    std::vector<std::string> names;
    for (auto& pair : getScripts()) {
        names.push_back(pair.first);
    }
    return names;
}

void ScriptRegistry::clear() {
    getScripts().clear();
}

std::vector<ScriptResult> NseEngine::httpDetection(const ScanResult& result) {
    std::vector<ScriptResult> results;
    
    if (result.port != 80 && result.port != 8080 && result.port != 443 && result.port != 8443) {
        return results;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return results;
    
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(result.port);
    
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        close(sock);
        return results;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return results;
    }
    
    std::string request = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    send(sock, request.c_str(), request.length(), 0);
    
    char buffer[4096] = {0};
    ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (len > 0) {
        ScriptResult sr;
        sr.name = "http-headers";
        sr.success = true;
        sr.output = buffer;
        
        if (std::string(buffer).find("Server:") != std::string::npos) {
            sr.fields["server"] = "detected";
        }
        if (std::string(buffer).find("X-Powered-By:") != std::string::npos) {
            sr.fields["tech"] = "detected";
        }
        
        results.push_back(sr);
    }
    
    close(sock);
    return results;
}

std::vector<ScriptResult> NseEngine::sshDetection(const ScanResult& result) {
    std::vector<ScriptResult> results;
    
    if (result.port != 22) return results;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return results;
    
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(result.port);
    
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        close(sock);
        return results;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return results;
    }
    
    char buffer[4096] = {0};
    ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (len > 0) {
        ScriptResult sr;
        sr.name = "ssh-banner";
        sr.success = true;
        sr.output = buffer;
        
        if (std::string(buffer).find("SSH-") != std::string::npos) {
            sr.fields["ssh"] = "detected";
        }
        
        results.push_back(sr);
    }
    
    close(sock);
    return results;
}

std::vector<ScriptResult> NseEngine::ftpDetection(const ScanResult& result) {
    std::vector<ScriptResult> results;
    
    if (result.port != 21) return results;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return results;
    
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(result.port);
    
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        close(sock);
        return results;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return results;
    }
    
    char buffer[4096] = {0};
    ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (len > 0) {
        ScriptResult sr;
        sr.name = "ftp-banner";
        sr.success = true;
        sr.output = buffer;
        
        if (std::string(buffer).find("220") != std::string::npos) {
            sr.fields["ftp"] = "detected";
        }
        
        results.push_back(sr);
    }
    
    close(sock);
    return results;
}

std::vector<ScriptResult> NseEngine::smtpDetection(const ScanResult& result) {
    std::vector<ScriptResult> results;
    
    if (result.port != 25 && result.port != 587) return results;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return results;
    
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(result.port);
    
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        close(sock);
        return results;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return results;
    }
    
    char buffer[4096] = {0};
    ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (len > 0) {
        ScriptResult sr;
        sr.name = "smtp-banner";
        sr.success = true;
        sr.output = buffer;
        
        if (std::string(buffer).find("220") != std::string::npos) {
            sr.fields["smtp"] = "detected";
        }
        
        results.push_back(sr);
    }
    
    close(sock);
    return results;
}

std::vector<ScriptResult> NseEngine::snmpDetection(const ScanResult& result) {
    std::vector<ScriptResult> results;
    
    if (result.port != 161 && result.port != 162) return results;
    
    ScriptResult sr;
    sr.name = "snmp-check";
    sr.success = true;
    sr.output = "SNMP port detected - consider running snmp-check";
    sr.fields["snmp"] = "detected";
    results.push_back(sr);
    
    return results;
}

void NseEngine::init() {
    registerBuiltInScripts();
}

void NseEngine::registerBuiltInScripts() {
    ScriptRegistry::registerScript("http", httpDetection);
    ScriptRegistry::registerScript("ssh", sshDetection);
    ScriptRegistry::registerScript("ftp", ftpDetection);
    ScriptRegistry::registerScript("smtp", smtpDetection);
    ScriptRegistry::registerScript("snmp", snmpDetection);
}

std::vector<ScriptResult> NseEngine::run(const ScanResult& result) {
    return ScriptRegistry::runScripts("default", result);
}

void NseEngine::loadScriptsFromDirectory(const std::string& dir) {
    std::cout << "Script directory: " << dir << " (not implemented)\n";
}
