#include "utils.hpp"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>
#include <cstdlib>
#include "types.hpp"

void validateIP(const std::string& ipStr) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) <= 0) {
        std::cerr << "Ошибка: IP-адрес '" << ipStr << "' введен неверно.\n";
        exit(1);
    }
}

std::vector<int> parsePorts(const std::string& portStr) {
    std::vector<int> ports;
    
    if (portStr.find(',') != std::string::npos) {
        std::istringstream iss(portStr);
        std::string token;
        while (std::getline(iss, token, ',')) {
            int port = std::stoi(token);
            if (port >= 1 && port <= 65535) {
                ports.push_back(port);
            }
        }
        std::sort(ports.begin(), ports.end());
        return ports;
    }
    
    if (portStr.find('-') != std::string::npos) {
        size_t dash = portStr.find('-');
        int start = std::stoi(portStr.substr(0, dash));
        int end = std::stoi(portStr.substr(dash + 1));
        
        if (start < 1 || end > 65535 || start > end) {
            std::cerr << "Ошибка: Неверный диапазон портов (1-65535).\n";
            exit(1);
        }
        
        for (int p = start; p <= end; ++p) {
            ports.push_back(p);
        }
        return ports;
    }
    
    int port = std::stoi(portStr);
    if (port >= 1 && port <= 65535) {
        ports.push_back(port);
    }
    return ports;
}

void printUsage(const char* prog) {
    std::cout << "Использование: " << prog << " <target> [опции]\n"
              << "Опции:\n"
              << "  -p, --ports     Диапазон или список портов (по умолчанию: 1-1024)\n"
              << "                   Примеры: 80, 1-1000, 22,80,443,8080\n"
              << "  -t, --threads   Количество потоков (по умолчанию: 100)\n"
              << "  --timeout      Тайм-аут в секундах (по умолчанию: 1.0)\n"
              << "  -s, --scan     Тип сканирования:\n"
              << "                  connect - TCP CONNECT (по умолчанию)\n"
              << "                  syn     - TCP SYN (требует root)\n"
              << "                  fin     - TCP FIN\n"
              << "                  xmas    - TCP Xmas\n"
              << "                  null    - TCP NULL\n"
              << "                  udp     - UDP сканирование\n"
              << "  -v, --version  Определение версии сервисов (banner grabbing)\n"
              << "Примеры:\n"
              << "  " << prog << " 192.168.1.1\n"
              << "  " << prog << " 192.168.1.1 -p 22,80,443\n"
              << "  " << prog << " 192.168.1.1 -s syn -p 1-1000\n"
              << "  " << prog << " 192.168.1.1 -v -p 80,443,3306\n";
}

ScanType parseScanType(const std::string& type) {
    if (type == "syn") return ScanType::SYN;
    if (type == "fin") return ScanType::FIN;
    if (type == "xmas") return ScanType::XMAS;
    if (type == "null") return ScanType::NULL_SCAN;
    if (type == "udp") return ScanType::UDP;
    return ScanType::CONNECT;
}

std::string scanTypeToString(ScanType type) {
    switch (type) {
        case ScanType::SYN: return "SYN";
        case ScanType::FIN: return "FIN";
        case ScanType::XMAS: return "XMAS";
        case ScanType::NULL_SCAN: return "NULL";
        case ScanType::UDP: return "UDP";
        default: return "CONNECT";
    }
}

ScanConfig parseArguments(int argc, char* argv[]) {
    ScanConfig config;
    
    if (argc < 2) {
        printUsage(argv[0]);
        exit(1);
    }
    
    config.target = argv[1];
    config.ports = parsePorts("1-1024");
    config.threads = 100;
    config.timeout = 1.0f;
    config.scanType = ScanType::CONNECT;
    config.detectVersion = false;
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            config.ports = parsePorts(argv[++i]);
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            config.threads = std::stoi(argv[++i]);
        } else if (arg == "--timeout" && i + 1 < argc) {
            config.timeout = std::stof(argv[++i]);
        } else if ((arg == "-s" || arg == "--scan") && i + 1 < argc) {
            config.scanType = parseScanType(argv[++i]);
        } else if (arg == "-v" || arg == "--version") {
            config.detectVersion = true;
        }
    }
    
    validateIP(config.target);
    
    return config;
}
