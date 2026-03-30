#include "scanner.hpp"

#include <iostream>
#include <algorithm>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string target = argv[1];
    std::string portStr = "1-1024";
    int threads = 100;
    float timeout = 1.0f;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            portStr = argv[++i];
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "--timeout" && i + 1 < argc) {
            timeout = std::stof(argv[++i]);
        }
    }

    validateIP(target);

    int startPort, endPort;
    parsePorts(portStr, startPort, endPort);

    int portCount = endPort - startPort + 1;
    threads = std::min(threads, portCount);

    std::cout << "Сканирование " << target << " (" << portCount
              << " портов) в " << threads << " потоков...\n";

    PortScanner scanner(target, startPort, endPort, threads, timeout);
    scanner.scan();

    return 0;
}
