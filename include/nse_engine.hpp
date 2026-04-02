#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include "types.hpp"

class ScriptResult {
public:
    std::string name;
    std::string output;
    std::map<std::string, std::string> fields;
    bool success;
};

class ScriptRegistry {
public:
    static void registerScript(const std::string& name, 
                              std::function<std::vector<ScriptResult>(const ScanResult&)> func);
    static std::vector<ScriptResult> runScripts(const std::string& port, const ScanResult& result);
    static std::vector<std::string> getAvailableScripts();
    static void clear();
    
private:
    static std::map<std::string, std::function<std::vector<ScriptResult>(const ScanResult&)>>& getScripts();
};

class NseEngine {
public:
    static void init();
    static std::vector<ScriptResult> run(const ScanResult& result);
    static void loadScriptsFromDirectory(const std::string& dir);
    static void registerBuiltInScripts();
    
private:
    static std::vector<ScriptResult> httpDetection(const ScanResult& result);
    static std::vector<ScriptResult> sshDetection(const ScanResult& result);
    static std::vector<ScriptResult> ftpDetection(const ScanResult& result);
    static std::vector<ScriptResult> smtpDetection(const ScanResult& result);
    static std::vector<ScriptResult> snmpDetection(const ScanResult& result);
};
