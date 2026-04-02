#include "port_database.hpp"

#include <map>
#include <string>

static const std::map<int, PortInfo>& getDatabase() {
    static std::map<int, PortInfo> db = {
        {20, {"ftp-data", "FTP Data - File Transfer Protocol (Data)", {}}},
        {21, {"ftp", "FTP - File Transfer Protocol (Control)", {"CVE-2020-7246", "CVE-2019-10149"}}},
        {22, {"ssh", "SSH - Secure Shell", {"CVE-2023-48795", "CVE-2023-46436"}}},
        {23, {"telnet", "Telnet - Unencrypted remote access", {"CVE-1999-0618"}}},
        {25, {"smtp", "SMTP - Simple Mail Transfer Protocol", {"CVE-2022-32221", "CVE-2022-36356"}}},
        {53, {"dns", "DNS - Domain Name System", {"CVE-2023-3341", "CVE-2023-28252"}}},
        {67, {"dhcp", "DHCP - Dynamic Host Configuration Protocol (Server)", {}}},
        {68, {"dhcp", "DHCP - Dynamic Host Configuration Protocol (Client)", {}}},
        {69, {"tftp", "TFTP - Trivial File Transfer Protocol", {}}},
        {80, {"http", "HTTP - Hypertext Transfer Protocol", {"CVE-2023-44487", "CVE-2023-4863"}}},
        {110, {"pop3", "POP3 - Post Office Protocol v3", {}}},
        {119, {"nntp", "NNTP - Network News Transfer Protocol", {}}},
        {123, {"ntp", "NTP - Network Time Protocol", {"CVE-2023-26360"}}},
        {135, {"msrpc", "Microsoft RPC", {"CVE-2023-21752"}}},
        {137, {"netbios-ns", "NetBIOS Name Service", {}}},
        {138, {"netbios-dgm", "NetBIOS Datagram Service", {}}},
        {139, {"netbios-ssn", "NetBIOS Session Service", {}}},
        {143, {"imap", "IMAP - Internet Message Access Protocol", {}}},
        {161, {"snmp", "SNMP - Simple Network Management Protocol", {"CVE-2023-29552"}}},
        {162, {"snmptrap", "SNMP Trap", {}}},
        {389, {"ldap", "LDAP - Lightweight Directory Access Protocol", {"CVE-2023-22809"}}},
        {443, {"https", "HTTPS - HTTP Secure", {"CVE-2023-44487", "CVE-2023-4863"}}},
        {445, {"microsoft-ds", "Microsoft Directory Services", {"CVE-2023-21752"}}},
        {465, {"smtps", "SMTP over SSL", {}}},
        {514, {"syslog", "Syslog - System Logging", {}}},
        {515, {"lpd", "LPD - Line Printer Daemon", {}}},
        {587, {"submission", "Mail Submission Agent", {}}},
        {636, {"ldaps", "LDAP over SSL", {}}},
        {993, {"imaps", "IMAP over SSL", {}}},
        {995, {"pop3s", "POP3 over SSL", {}}},
        {1080, {"socks", "SOCKS Proxy", {}}},
        {1433, {"mssql", "Microsoft SQL Server", {"CVE-2023-29380"}}},
        {1434, {"mssql-msql", "Microsoft SQL Server Browser", {}}},
        {1521, {"oracle", "Oracle Database", {"CVE-2023-21720"}}},
        {1723, {"pptp", "PPTP - Point-to-Point Tunneling Protocol", {"CVE-2023-38156"}}},
        {2049, {"nfs", "NFS - Network File System", {"CVE-2023-20598"}}},
        {2082, {"cpanel", "cPanel", {}}},
        {2083, {"cpanel-ssl", "cPanel SSL", {}}},
        {2181, {"zookeeper", "Apache ZooKeeper", {"CVE-2023-37582"}}},
        {3000, {"nodejs", "Node.js Dev Server", {"CVE-2023-30536"}}},
        {3306, {"mysql", "MySQL Database", {"CVE-2023-22006"}}},
        {3389, {"rdp", "RDP - Remote Desktop Protocol", {"CVE-2023-38090"}}},
        {4369, {"epmd", "Erlang Port Mapper Daemon", {}}},
        {5000, {"flask", "Flask Dev Server", {}}},
        {5060, {"sip", "SIP - Session Initiation Protocol", {"CVE-2023-31017"}}},
        {5222, {"xmpp", "XMPP - Extensible Messaging", {}}},
        {5432, {"postgresql", "PostgreSQL Database", {"CVE-2023-39442"}}},
        {5672, {"amqp", "AMQP - Advanced Message Queuing Protocol", {}}},
        {5900, {"vnc", "VNC - Virtual Network Computing", {"CVE-2023-28370"}}},
        {5984, {"couchdb", "CouchDB", {"CVE-2023-26230"}}},
        {6379, {"redis", "Redis Database", {"CVE-2023-22456"}}},
        {6443, {"kubernetes", "Kubernetes API Server", {"CVE-2023-44487"}}},
        {6667, {"irc", "IRC - Internet Relay Chat", {}}},
        {8000, {"http-alt", "HTTP Alternative", {}}},
        {8008, {"http-alt", "HTTP Alternative", {}}},
        {8080, {"http-proxy", "HTTP Proxy", {"CVE-2023-44487"}}},
        {8443, {"https-alt", "HTTPS Alternative", {}}},
        {8888, {"http-alt", "HTTP Alternative", {}}},
        {9000, {"php-fpm", "PHP FastCGI Process Manager", {"CVE-2023-34979"}}},
        {9090, {"prometheus", "Prometheus Metrics", {"CVE-2023-22311"}}},
        {9200, {"elasticsearch", "Elasticsearch", {"CVE-2023-28567"}}},
        {9300, {"elasticsearch", "Elasticsearch Transport", {}}},
        {11211, {"memcached", "Memcached", {"CVE-2023-26768"}}},
        {27017, {"mongodb", "MongoDB", {"CVE-2023-27957"}}},
        {27018, {"mongodb", "MongoDB Shard", {}}},
        {27019, {"mongodb", "MongoDB Config", {}}},
        {50000, {"sap", "SAP", {"CVE-2023-27559"}}},
    };
    return db;
}

const PortInfo& PortDatabase::getInfo(int port) {
    static const PortInfo unknown = {"unknown", "Unknown service", {}};
    const auto& db = getDatabase();
    auto it = db.find(port);
    if (it != db.end()) {
        return it->second;
    }
    return unknown;
}

std::string PortDatabase::getServiceName(int port) {
    return getInfo(port).service;
}

bool PortDatabase::isKnownPort(int port) {
    return getDatabase().find(port) != getDatabase().end();
}

std::vector<std::string> PortDatabase::getCves(int port) {
    return getInfo(port).cves;
}
