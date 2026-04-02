#include "scanner.hpp"

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include "port_database.hpp"
#include "types.hpp"

PortScanner::PortScanner(const std::string& target, const std::vector<int>& ports, int threads, float timeout, ScanType scanType, bool detectVersion)
    : target_(target), ports_(ports), threads_(threads), 
      timeout_(timeout), scanType_(scanType), 
      detectVersion_(detectVersion), openCount_(0) {}

std::vector<ScanResult> PortScanner::scan() {
    std::vector<ScanResult> results;
    std::vector<std::thread> workers;
    std::atomic<int> portIndex(0);

    auto startTime = std::chrono::steady_clock::now();

    for (int i = 0; i < threads_; ++i) {
        workers.emplace_back([this, &portIndex, &results]() {
            worker(portIndex, results);
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

    return results;
}

void PortScanner::worker(std::atomic<int>& portIndex, std::vector<ScanResult>& results) {
    while (true) {
        int idx = portIndex.fetch_add(1);
        if (idx >= static_cast<int>(ports_.size())) break;

        int port = ports_[idx];
        bool isOpen = scanPort(port);
        
        if (isOpen) {
            openCount_++;
            
            ScanResult result;
            result.port = port;
            result.protocol = (scanType_ == ScanType::UDP) ? "udp" : "tcp";
            result.service = getServiceInfo(port);
            
            if (detectVersion_ && port != 53 && port != 161) 
                result.version = grabBanner(port);
            
            
            const PortInfo& info = PortDatabase::getInfo(port);
            result.description = info.description;
            
            results.push_back(result);

            std::lock_guard<std::mutex> lock(printMutex_);
            std::cout << "[+] " << port << "/" << result.protocol << " | " << result.service;

            if (!result.version.empty()) 
                std::cout << " | " << result.version;
            
            if (!result.description.empty() && result.description != info.service) 
                std::cout << " | " << result.description;
            
            std::cout << "\n";
        }
    }
}

bool PortScanner::scanPort(int port) {
    if (scanType_ == ScanType::UDP) {
        return sendUdpProbe(port);
    }
    return sendTcpProbe(port);
}

bool PortScanner::sendTcpProbe(int port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) 
        return sendTcpProbeFallback(port);

    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    struct iphdr* iph = (struct iphdr*)malloc(sizeof(struct iphdr) + sizeof(struct tcphdr));
    struct tcphdr* tcph = (struct tcphdr*)(iph + 1);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_.c_str(), &dest.sin_addr);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = 0;
    iph->daddr = dest.sin_addr.s_addr;

    tcph->source = htons(rand() % 65535);
    tcph->dest = htons(port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;

    switch (scanType_) {
        case ScanType::SYN:
            tcph->syn = 1;
            break;
        case ScanType::FIN:
            tcph->fin = 1;
            break;
        case ScanType::XMAS:
            tcph->fin = 1;
            tcph->psh = 1;
            tcph->urg = 1;
            break;
        case ScanType::NULL_SCAN:
            break;
        default:
            tcph->syn = 1;
    }

    tcph->rst = 0;
    tcph->ack = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memcpy(packet, iph, sizeof(struct iphdr) + sizeof(struct tcphdr));

    sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest));

    fd_set readfds;
    struct timeval tv;
    tv.tv_sec = static_cast<int>(timeout_);
    tv.tv_usec = static_cast<int>((timeout_ - static_cast<int>(timeout_)) * 1000000);

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    bool open = false;
    char buffer[4096];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    if (select(sock + 1, &readfds, nullptr, nullptr, &tv) > 0) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, 
                               (struct sockaddr*)&src_addr, &addr_len);
        if (len > 0) {
            struct iphdr* resp_ip = (struct iphdr*)buffer;
            struct tcphdr* resp_tcp = (struct tcphdr*)(buffer + resp_ip->ihl * 4);

            if (resp_tcp->source == tcph->dest) {
                switch (scanType_) {
                    case ScanType::SYN:
                    case ScanType::CONNECT:
                        if (resp_tcp->syn && resp_tcp->ack) open = true;
                        break;
                    case ScanType::FIN:
                    case ScanType::XMAS:
                    case ScanType::NULL_SCAN:
                        if (!resp_tcp->rst) open = true;
                        break;
                    default:
                        break;
                }
            }
        }
    }

    free(iph);
    close(sock);
    return open;
}

bool PortScanner::sendTcpProbeFallback(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

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

    bool result = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    return result;
}

bool PortScanner::sendUdpProbe(int port) {
    int udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSock < 0) return false;

    int icmpSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    bool useIcmp = (icmpSock >= 0);
    if (useIcmp) {
        int enable = 1;
        setsockopt(icmpSock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    }

    struct timeval tv;
    tv.tv_sec = static_cast<int>(timeout_);
    tv.tv_usec = static_cast<int>((timeout_ - static_cast<int>(timeout_)) * 1000000);
    setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &addr.sin_addr);

    bool open = false;
    bool filtered = false;
    int probes = 3;

    for (int attempt = 0; attempt < probes && !open; ++attempt) {
        char packet[4] = {0};
        sendto(udpSock, packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr));

        char buffer[4096];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(udpSock, &readfds);
        if (useIcmp) FD_SET(icmpSock, &readfds);
        
        int maxFd = useIcmp ? std::max(udpSock, icmpSock) : udpSock;
        int selected = select(maxFd + 1, &readfds, nullptr, nullptr, &tv);

        if (selected > 0) {
            if (useIcmp && FD_ISSET(icmpSock, &readfds)) {
                ssize_t len = recvfrom(icmpSock, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&src_addr, &addr_len);
                if (len > 0) {
                    struct iphdr* iph = (struct iphdr*)buffer;
                    if (iph->protocol == IPPROTO_ICMP) {
                        struct icmphdr* icmp = (struct icmphdr*)(buffer + iph->ihl * 4);
                        if (icmp->type == ICMP_DEST_UNREACH) {
                            filtered = true;
                            break;
                        }
                    }
                }
            }

            if (FD_ISSET(udpSock, &readfds)) {
                ssize_t len = recvfrom(udpSock, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&src_addr, &addr_len);
                if (len > 0) {
                    open = true;
                }
            }
        } else if (selected == 0) {
            if (attempt == probes - 1) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    if (icmpSock >= 0) close(icmpSock);
    close(udpSock);

    if (filtered) return false;
    return open;
}

std::string PortScanner::grabBanner(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv;
    tv.tv_sec = static_cast<int>(timeout_);
    tv.tv_usec = static_cast<int>((timeout_ - static_cast<int>(timeout_)) * 1000000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return "";
    }

    char buffer[256] = {0};
    std::string response;
    
    if (port == 80 || port == 8080 || port == 8000 || port == 8888) {
        const char* request = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        send(sock, request, strlen(request), 0);
    }

    ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (len > 0) {
        buffer[len] = '\0';
        response = buffer;
        
        size_t pos = response.find("\r\n");
        if (pos != std::string::npos) 
            response = response.substr(0, pos);

        pos = response.find("\n");

        if (pos != std::string::npos) 
            response = response.substr(0, pos);
        
        if (response.length() > 100) 
            response = response.substr(0, 100);
    }

    close(sock);
    return response;
}

std::string PortScanner::getServiceInfo(int port) const {
    return PortDatabase::getServiceName(port);
}
