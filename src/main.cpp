#include "utils.hpp"
#include "scanner.hpp"

#include <iostream>
#include <algorithm>

int main(int argc, char* argv[]) {
    ScanConfig config = parseArguments(argc, argv);

    int portCount = static_cast<int>(config.ports.size());
    int threads = std::min(config.threads, portCount);

    std::cout << "Сканирование " << config.target << " (" << portCount << " портов) в " 
              << threads << " потоков...\n"
              << "Тип сканирования: " << scanTypeToString(config.scanType) << "\n";

    if (config.detectVersion) {
        std::cout << "Определение версий: включено\n";
    }

    PortScanner scanner(config.target, config.ports, threads, config.timeout, config.scanType, config.detectVersion);
    scanner.scan();

    return 0;
}
