#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

class Logger {
public:
    static void init(const std::string& filename, LogLevel level = LogLevel::INFO);
    static void close();
    
    static void debug(const std::string& msg);
    static void info(const std::string& msg);
    static void warning(const std::string& msg);
    static void error(const std::string& msg);
    
    static void setLevel(LogLevel level);
    static bool isInitialized();
    
private:
    static std::string levelToString(LogLevel level);
    static std::string getTimestamp();
    static void write(LogLevel level, const std::string& msg);
    
    static std::ofstream file_;
    static std::mutex mutex_;
    static LogLevel minLevel_;
    static bool initialized_;
};
