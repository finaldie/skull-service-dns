#ifndef ASYNC_DNSCLIENT_CACHE_H
#define ASYNC_DNSCLIENT_CACHE_H

#include <ares.h>
#include <time.h>

#include <string>
#include <vector>
#include <map>

#include <skullcpp/api.h>

namespace adns {

class Cache : public skullcpp::ServiceData {
public:
    typedef struct DnsRecords {
        time_t start_;
        std::vector<ares_addrttl> records_;
    } DnsRecords;

    // Well formatted record
    typedef struct rDnsRecord {
        std::string ip;
        int         ttl;
    } rDnsRecords;

    typedef std::vector<rDnsRecord> RDnsRecordVec;

private:
    // domain <--> record
    std::map<std::string, DnsRecords> records_;

    // name servers
    std::vector<std::string> nservers_;

public:
    Cache();
    ~Cache();

public:
    void queryFromCache(const skullcpp::Service& service,
                        const std::string& domain,
                        RDnsRecordVec& rRecords) const;

    bool queryFromDNS(const skullcpp::Service& service,
                      const std::string& domain, bool updateOnly) const;

    void updateCache(skullcpp::Service& service, const std::string& domain,
                     DnsRecords& records);

private:
    void initNameServers();

    const std::string& getNameServerIP() const;
};

} // End of namespace

#endif

