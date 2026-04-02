#include <gtest/gtest.h>
#include "../include/types.hpp"
#include "../include/port_database.hpp"
#include "../include/exporter.hpp"
#include "../include/config.hpp"

TEST(PortDatabaseTest, GetKnownPort) {
    PortInfo info = PortDatabase::getInfo(22);
    EXPECT_EQ(info.service, "ssh");
    EXPECT_EQ(info.description, "SSH - Secure Shell");
}

TEST(PortDatabaseTest, GetUnknownPort) {
    PortInfo info = PortDatabase::getInfo(99999);
    EXPECT_EQ(info.service, "unknown");
}

TEST(PortDatabaseTest, GetCvesForPort) {
    std::vector<std::string> cves = PortDatabase::getCves(22);
    EXPECT_FALSE(cves.empty());
}

TEST(ConfigTest, ParsePortsComma) {
    ScanConfig config;
    config.ports = Config::parsePortsFromConfig("22,80,443");
    EXPECT_EQ(config.ports.size(), 3);
    EXPECT_EQ(config.ports[0], 22);
}

TEST(ConfigTest, ParsePortsRange) {
    ScanConfig config;
    config.ports = Config::parsePortsFromConfig("80-82");
    EXPECT_EQ(config.ports.size(), 3);
    EXPECT_EQ(config.ports[0], 80);
}

TEST(ExporterTest, ExportToJson) {
    std::vector<ScanResult> results;
    ScanResult r;
    r.port = 80;
    r.protocol = "tcp";
    r.service = "http";
    r.version = "Apache 2.4";
    r.description = "HTTP server";
    results.push_back(r);
    
    std::string json = ResultExporter::resultsToJson(results);
    EXPECT_TRUE(json.find("\"port\": 80") != std::string::npos);
    EXPECT_TRUE(json.find("\"service\": \"http\"") != std::string::npos);
}

TEST(ExporterTest, ParseJsonResults) {
    std::string json = R"({"results":[{"port":80,"protocol":"tcp","service":"http","version":"","description":""}]})";
    std::vector<ScanResult> results;
    bool success = ResultExporter::parseResultsFromJson(json, results);
    EXPECT_TRUE(success);
    EXPECT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].port, 80);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
