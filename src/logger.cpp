#include "logger.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

std::ofstream Logger::file_;
std::mutex Logger::mutex_;
LogLevel Logger::minLevel_ = LogLevel::INFO;
bool Logger::initialized_ = false;

void Logger::init(const std::string& filename, LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        close();
    }
    
    file_.open(filename, std::ios::app);
    minLevel_ = level;
    initialized_ = file_.is_open();
}

void Logger::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (file_.is_open()) {
        file_.close();
    }
    initialized_ = false;
}

void Logger::setLevel(LogLevel level) {
    minLevel_ = level;
}

bool Logger::isInitialized() {
    return initialized_;
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR:   return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string Logger::getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

void Logger::write(LogLevel level, const std::string& msg) {
    if (level < minLevel_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ostringstream ss;
    ss << "[" << getTimestamp() << "] ";
    ss << "[" << levelToString(level) << "] ";
    ss << msg;
    
    std::string line = ss.str();
    
    if (file_.is_open()) {
        file_ << line << std::endl;
        file_.flush();
    }
    
    if (level >= LogLevel::ERROR || level == LogLevel::INFO) {
        std::cout << line << std::endl;
    }
}

void Logger::debug(const std::string& msg) {
    write(LogLevel::DEBUG, msg);
}

void Logger::info(const std::string& msg) {
    write(LogLevel::INFO, msg);
}

void Logger::warning(const std::string& msg) {
    write(LogLevel::WARNING, msg);
}

void Logger::error(const std::string& msg) {
    write(LogLevel::ERROR, msg);
}
