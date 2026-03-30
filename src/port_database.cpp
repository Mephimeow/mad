#include "port_database.hpp"

#include <map>
#include <string>

static const std::map<int, PortInfo>& getDatabase() {
    static std::map<int, PortInfo> db = {
        {20, {"ftp-data", "FTP Data - File Transfer Protocol (Data)"}},
        {21, {"ftp", "FTP - File Transfer Protocol (Control)"}},
        {22, {"ssh", "SSH - Secure Shell"}},
        {23, {"telnet", "Telnet - Unencrypted remote access"}},
        {25, {"smtp", "SMTP - Simple Mail Transfer Protocol"}},
        {53, {"dns", "DNS - Domain Name System"}},
        {67, {"dhcp", "DHCP - Dynamic Host Configuration Protocol (Server)"}},
        {68, {"dhcp", "DHCP - Dynamic Host Configuration Protocol (Client)"}},
        {69, {"tftp", "TFTP - Trivial File Transfer Protocol"}},
        {80, {"http", "HTTP - Hypertext Transfer Protocol"}},
        {110, {"pop3", "POP3 - Post Office Protocol v3"}},
        {119, {"nntp", "NNTP - Network News Transfer Protocol"}},
        {123, {"ntp", "NTP - Network Time Protocol"}},
        {135, {"msrpc", "MSRPC - Microsoft RPC"}},
        {137, {"netbios-ns", "NetBIOS Name Service"}},
        {138, {"netbios-dgm", "NetBIOS Datagram Service"}},
        {139, {"netbios-ssn", "NetBIOS Session Service"}},
        {143, {"imap", "IMAP - Internet Message Access Protocol"}},
        {161, {"snmp", "SNMP - Simple Network Management Protocol"}},
        {162, {"snmptrap", "SNMP Trap"}},
        {389, {"ldap", "LDAP - Lightweight Directory Access Protocol"}},
        {443, {"https", "HTTPS - HTTP Secure"}},
        {445, {"microsoft-ds", "Microsoft Directory Services"}},
        {465, {"smtps", "SMTP over SSL"}},
        {514, {"syslog", "Syslog - System Logging"}},
        {515, {"lpd", "LPD - Line Printer Daemon"}},
        {587, {"submission", "Mail Submission Agent"}},
        {636, {"ldaps", "LDAP over SSL"}},
        {993, {"imaps", "IMAP over SSL"}},
        {995, {"pop3s", "POP3 over SSL"}},
        {1080, {"socks", "SOCKS Proxy"}},
        {1433, {"mssql", "Microsoft SQL Server"}},
        {1434, {"mssql-msql", "Microsoft SQL Server Browser"}},
        {1521, {"oracle", "Oracle Database"}},
        {1723, {"pptp", "PPTP - Point-to-Point Tunneling Protocol"}},
        {2049, {"nfs", "NFS - Network File System"}},
        {2082, {"cpanel", "cPanel"}},
        {2083, {"cpanel-ssl", "cPanel SSL"}},
        {2181, {"zookeeper", "Apache ZooKeeper"}},
        {3000, {"nodejs", "Node.js Dev Server"}},
        {3306, {"mysql", "MySQL Database"}},
        {3389, {"rdp", "RDP - Remote Desktop Protocol"}},
        {4369, {"epmd", "Erlang Port Mapper Daemon"}},
        {5000, {"flask", "Flask Dev Server"}},
        {5060, {"sip", "SIP - Session Initiation Protocol"}},
        {5222, {"xmpp", "XMPP - Extensible Messaging"}},
        {5432, {"postgresql", "PostgreSQL Database"}},
        {5672, {"amqp", "AMQP - Advanced Message Queuing Protocol"}},
        {5900, {"vnc", "VNC - Virtual Network Computing"}},
        {5984, {"couchdb", "CouchDB"}},
        {6379, {"redis", "Redis Database"}},
        {6443, {"kubernetes", "Kubernetes API Server"}},
        {6667, {"irc", "IRC - Internet Relay Chat"}},
        {8000, {"http-alt", "HTTP Alternative"}},
        {8008, {"http-alt", "HTTP Alternative"}},
        {8080, {"http-proxy", "HTTP Proxy"}},
        {8443, {"https-alt", "HTTPS Alternative"}},
        {8888, {"http-alt", "HTTP Alternative"}},
        {9000, {"php-fpm", "PHP FastCGI Process Manager"}},
        {9090, {"prometheus", "Prometheus Metrics"}},
        {9200, {"elasticsearch", "Elasticsearch"}},
        {9300, {"elasticsearch", "Elasticsearch Transport"}},
        {11211, {"memcached", "Memcached"}},
        {27017, {"mongodb", "MongoDB"}},
        {27018, {"mongodb", "MongoDB Shard"}},
        {27019, {"mongodb", "MongoDB Config"}},
        {50000, {"sap", "SAP"}},
    };
    return db;
}

const PortInfo& PortDatabase::getInfo(int port) {
    static const PortInfo unknown = {"unknown", "Unknown service"};
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
