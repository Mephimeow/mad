#include "utils.hpp"
#include "scanner.hpp"
#include "exporter.hpp"
#include "logger.hpp"
#include "config.hpp"

#include <iostream>
#include <algorithm>
#include <fstream>

int main(int argc, char* argv[]) {
    ScanConfig config;
    bool useConfigFile = false;
    std::string configFile;
    std::string outputFile;
    ExportFormat exportFormat = ExportFormat::TEXT;
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                configFile = argv[++i];
                useConfigFile = true;
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
        } else if (arg == "-f" || arg == "--format") {
            if (i + 1 < argc) {
                std::string fmt = argv[++i];
                if (fmt == "json") exportFormat = ExportFormat::JSON;
                else if (fmt == "xml") exportFormat = ExportFormat::XML;
                else if (fmt == "csv") exportFormat = ExportFormat::CSV;
                else if (fmt == "txt") exportFormat = ExportFormat::TEXT;
            }
        } else if (arg == "--log") {
            if (i + 1 < argc) {
                Logger::init(argv[++i]);
            }
        }
    }
    
    if (useConfigFile) {
        if (!Config::loadFromFile(configFile, config)) {
            std::cerr << "Ошибка загрузки конфигурации из файла: " << configFile << "\n";
            return 1;
        }
    } else {
        config = parseArguments(argc, argv);
    }
    
    Logger::info("Начало сканирования " + config.target);
    
    int portCount = static_cast<int>(config.ports.size());
    int threads = std::min(config.threads, portCount);

    std::cout << "Сканирование " << config.target << " (" << portCount << " портов) в " 
              << threads << " потоков...\n"
              << "Тип сканирования: " << scanTypeToString(config.scanType) << "\n";

    if (config.detectVersion) {
        std::cout << "Определение версий: включено\n";
    }

    PortScanner scanner(config.target, config.ports, threads, config.timeout, config.scanType, config.detectVersion);
    std::vector<ScanResult> results = scanner.scan();
    
    Logger::info("Сканирование завершено. Найдено " + std::to_string(results.size()) + " открытых портов");
    
    if (!outputFile.empty()) {
        if (ResultExporter::exportResults(results, outputFile, exportFormat)) {
            Logger::info("Результаты сохранены в файл: " + outputFile);
            std::cout << "Результаты сохранены в файл: " << outputFile << "\n";
        } else {
            Logger::error("Ошибка сохранения результатов в файл: " + outputFile);
            std::cerr << "Ошибка сохранения результатов\n";
        }
    }
    
    Logger::close();
    return 0;
}
