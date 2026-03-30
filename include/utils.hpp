#pragma once

#include <string>
#include <vector>
#include "types.hpp"

void validateIP(const std::string& ipStr);
std::vector<int> parsePorts(const std::string& portStr);
void printUsage(const char* prog);
ScanType parseScanType(const std::string& type);
std::string scanTypeToString(ScanType type);
ScanConfig parseArguments(int argc, char* argv[]);
