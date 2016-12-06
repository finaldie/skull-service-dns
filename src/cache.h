#ifndef ASYNC_DNSCLIENT_CACHE_H
#define ASYNC_DNSCLIENT_CACHE_H

#include <time.h>

#include <string>
#include <vector>
#include <map>

#include <skullcpp/api.h>

namespace adns {

class Cache : public skullcpp::ServiceData {
public:
    typedef enum QType {
        A    = 1,
        AAAA = 2
    } QType;

    // Well formatted record
    typedef struct RDnsRecord {
        std::string ip;
        int         ttl;
    } rDnsRecords;

    typedef std::vector<RDnsRecord> RDnsRecordVec;

    typedef struct DnsRecords {
        time_t start_;
        RDnsRecordVec records_;
    } DnsRecords;

private:
    // domain <--> record
    std::map<std::string, DnsRecords> recordsA_;
    std::map<std::string, DnsRecords> records4A_;

    // name servers
    std::vector<std::string> nservers_;

public:
    Cache();
    ~Cache();

public:
    void queryFromCache(const skullcpp::Service& service,
                        const std::string& domain,
                        QType qtype,
                        RDnsRecordVec& rRecords) const;

    bool queryFromDNS(const skullcpp::Service& service,
                      const std::string& domain, QType qtype) const;

    void updateCache(skullcpp::Service& service, const std::string& domain,
                     QType qtype, DnsRecords& records);

private:
    void initNameServers();

    const std::string& getNameServerIP() const;
};

} // End of namespace

#endif

