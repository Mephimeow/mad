#include "scanner.hpp"

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <algorithm>

PortScanner::PortScanner(const std::string& target, int startPort, int endPort,
                         int threads, float timeout)
    : target_(target), startPort_(startPort), endPort_(endPort),
      threads_(threads), timeout_(timeout), openCount_(0) {}

void PortScanner::scan() {
    std::vector<std::thread> workers;
    std::atomic<int> currentPort(startPort_);

    auto startTime = std::chrono::steady_clock::now();

    for (int i = 0; i < threads_; ++i) {
        workers.emplace_back([this, &currentPort]() {
            worker(currentPort);
        });
    }

    for (auto& t : workers) {
        t.join();
    }

    auto duration = std::chrono::steady_clock::now() - startTime;

    std::lock_guard<std::mutex> lock(printMutex_);
    std::cout << "\nСканирование завершено за "
              << std::chrono::duration<float>(duration).count() << " сек.\n"
              << "Открыто портов: " << openCount_.load() << "\n";
}

void PortScanner::worker(std::atomic<int>& portCounter) {
    while (true) {
        int port = portCounter.fetch_add(1);
        if (port > endPort_) break;
        scanPort(port);
    }
}

void PortScanner::scanPort(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct timeval tv;
    tv.tv_sec = static_cast<int>(timeout_);
    tv.tv_usec = static_cast<int>((timeout_ - static_cast<int>(timeout_)) * 1000000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string service = getServiceName(port);
        std::lock_guard<std::mutex> lock(printMutex_);
        std::cout << "[+] " << port << "/tcp  | " << service << "\n";
        openCount_++;
    }

    close(sock);
}

std::string PortScanner::getServiceName(int port) const {
    struct servent* service = getservbyport(htons(port), "tcp");
    return service ? std::string(service->s_name) : "unknown";
}

void validateIP(const std::string& ipStr) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) <= 0) {
        std::cerr << "Ошибка: IP-адрес '" << ipStr << "' введен неверно.\n";
        exit(1);
    }
}

void parsePorts(const std::string& portStr, int& start, int& end) {
    size_t dash = portStr.find('-');
    if (dash != std::string::npos) {
        start = std::stoi(portStr.substr(0, dash));
        end = std::stoi(portStr.substr(dash + 1));
    } else {
        start = end = std::stoi(portStr);
    }

    if (start < 1 || end > 65535 || start > end) {
        std::cerr << "Ошибка: Неверный диапазон портов (1-65535).\n";
        exit(1);
    }
}

void printUsage(const char* prog) {
    std::cout << "Использование: " << prog << " <target> [опции]\n"
              << "Опции:\n"
              << "  -p, --ports    Диапазон портов (по умолчанию: 1-1024)\n"
              << "  -t, --threads  Количество потоков (по умолчанию: 100)\n"
              << "  --timeout     Тайм-аут в секундах (по умолчанию: 1.0)\n"
              << "Примеры:\n"
              << "  " << prog << " 192.168.1.1\n"
              << "  " << prog << " 192.168.1.1 -p 80\n"
              << "  " << prog << " 192.168.1.1 -p 1-1000 -t 200\n";
}
