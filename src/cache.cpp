#include <stdlib.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <iostream>
#include <memory>

#include "cache.h"
#include "skull_protos.h"

using namespace skull::service::dns;

#define MAX_DNS_REPLY_ADDRS 100
#define IPV4_MAX_LENGTH     16
#define MAX_RECORD_EXPIRED_TIME 2  // unit: second

// ====================== Internal Functions ===================================
class UpdateJobdata {
private:
    std::string domain_;
    adns::Cache::DnsRecords records_;

public:
    UpdateJobdata(const std::string& domain) {
        this->domain_ = domain;
        this->records_.start_ = time(NULL);
    }

    void append(ares_addrttl addr) {
        this->records_.records_.push_back(addr);
    }

    const std::string& domain() const {
        return this->domain_;
    }

    adns::Cache::DnsRecords& records() {
        return this->records_;
    }

    const adns::Cache::DnsRecords& records() const {
        return this->records_;
    }
};

static
void _dnsrecord_updating(skullcpp::Service& service,
                         const std::shared_ptr<UpdateJobdata>& jobData) {
    auto dnsCache = (adns::Cache*)service.get();

    if (!jobData.get()) return;
    if (jobData->domain().empty()) return;
    if (jobData->records().records_.empty()) return;

    const std::string& domain = jobData->domain();
    adns::Cache::DnsRecords& records = jobData->records();

    dnsCache->updateCache(service, domain, records);
    SKULLCPP_LOG_INFO("RecordUpdating", "dnsrecord_updating done, domain: " << domain);
}

// dns callback functions
static
ssize_t _dns_reply_unpack(const void* data, size_t len)
{
    SKULLCPP_LOG_DEBUG("EPClient dns _unpack len: " << len);
    return (ssize_t)len;
}

static
void _ep_cb(const skullcpp::Service& service, skullcpp::EPClientRet& ret,
            std::shared_ptr<std::string>& domain)
{
    // TODO:
    //  need double verify whether really needs to query dns server

    // 1. Prepare and validate ep status
    SKULLCPP_LOG_DEBUG("dns _ep_cb: response len: " << ret.responseSize()
                       << ", status: " << ret.status()
                       << ", latency: " << ret.latency());

    auto& apiData   = ret.apiData();
    auto& queryReq  = (const query_req&)apiData.request();
    auto& queryResp = (query_resp&)apiData.response();

    if (ret.status() != skullcpp::EPClient::Status::OK) {
        SKULLCPP_LOG_ERROR("svc.dns.query-3",
                        "dns query failed due to network issue",
                        "Check network or dns server status");

        queryResp.set_code(1);
        queryResp.set_error("Dns query failed");
        return;
    }

    // 2. Parse dns answers
    int naddrs = MAX_DNS_REPLY_ADDRS;
    struct ares_addrttl addrs[MAX_DNS_REPLY_ADDRS];
    memset(addrs, 0, sizeof(struct ares_addrttl) * MAX_DNS_REPLY_ADDRS);
    auto response = (const unsigned char *)ret.response();

    int r = ares_parse_a_reply(response, (int)ret.responseSize(),
                               NULL, addrs, &naddrs);

    if (r != ARES_SUCCESS) {
        SKULLCPP_LOG_ERROR("svc.dns.query-4", "dns parse reply failed: "
            << ares_strerror(r)
            << " domain: " << queryReq.question(),
            "Check whether queried domain is correct");

        queryResp.set_code(1);
        queryResp.set_error("Dns query failed, check whether domain is correct");
        return;
    } else {
        SKULLCPP_LOG_DEBUG("Got " << naddrs << " dns records");
    }

    if (!naddrs) {
        queryResp.set_code(1);
        queryResp.set_error("Dns query failed, no ip returned");
        return;
    }

    // 3. Fill the api response
    queryResp.set_code(0);
    auto jobData = std::make_shared<UpdateJobdata>(queryReq.question());

    for (int i = 0; i < naddrs; i++) {
        // 1. Fill jobData for updating the cache
        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &addrs[i].ipaddr, ip, IPV4_MAX_LENGTH);
        jobData->append(addrs[i]);

        SKULLCPP_LOG_DEBUG(" - ip: " << ip << "; ttl: " << addrs[i].ttl);

        // 2. Fill the service response
        auto* record = queryResp.add_record();
        record->set_ip(ip);
        record->set_ttl(addrs[i].ttl);
    }

    // 4. Update it via a service job
    service.createJob(0, 0, skull_BindSvcJobNPW(_dnsrecord_updating, jobData), NULL);
}

static
void _ep_cb_updateonly(const skullcpp::Service& service,
                       skullcpp::EPClientRet& ret,
                       std::shared_ptr<std::string>& domain)
{
    // 1. Prepare and validate ep status
    SKULLCPP_LOG_DEBUG("dns _ep_cb_updateonly: response len: "
              << ret.responseSize()
              << ", status: "  << ret.status()
              << ", latency: " << ret.latency());

    if (ret.status() != skullcpp::EPClient::Status::OK) {
        SKULLCPP_LOG_ERROR("svc.dns.query-3",
                        "dns query failed due to network issue",
                        "Check network or dns server status");
        return;
    }

    // 2. Parse dns answers
    int naddrs = MAX_DNS_REPLY_ADDRS;
    struct ares_addrttl addrs[MAX_DNS_REPLY_ADDRS];
    memset(addrs, 0, sizeof(struct ares_addrttl) * MAX_DNS_REPLY_ADDRS);
    auto response = (const unsigned char *)ret.response();

    int r = ares_parse_a_reply(response, (int)ret.responseSize(),
                               NULL, addrs, &naddrs);

    if (r != ARES_SUCCESS) {
        SKULLCPP_LOG_ERROR("svc.dns.query-4", "dns parse reply failed: "
            << ares_strerror(r)
            << " domain: " << domain,
            "Check whether queried domain is correct");
        return;
    } else {
        SKULLCPP_LOG_DEBUG("Got " << naddrs << " dns replies");
    }

    if (!naddrs) {
        return;
    }

    // 3. Fill the api response
    auto jobData = std::make_shared<UpdateJobdata>(*domain);

    for (int i = 0; i < naddrs; i++) {
        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &addrs[i].ipaddr, ip, IPV4_MAX_LENGTH);
        jobData->append(addrs[i]);

        SKULLCPP_LOG_DEBUG(" - ip: " << ip << "; ttl: " << addrs[i].ttl);
    }

    // 4. Update it via a service job
    service.createJob(0, 0, skull_BindSvcJobNPW(_dnsrecord_updating, jobData), NULL);
}

static
void _refresh_domain_records(skullcpp::Service& service,
                             const std::shared_ptr<std::string>& domain) {
    auto dnsCache = (adns::Cache*)service.get();

    bool ret = dnsCache->queryFromDNS(service, *domain, true);
    if (!ret) {
        SKULLCPP_LOG_ERROR("RefreshRecords", "Query domain failed: " << domain,
                           "Check the internet connection");
    } else {
        SKULLCPP_LOG_INFO("RefreshRecords", "Query domain success: " << domain);
    }
}

namespace adns {

Cache::Cache() {
    // 1. Init ares library
    int ret = ares_library_init(ARES_LIB_INIT_ALL);
    if (ret) {
        SKULLCPP_LOG_FATAL("Init", "Init ares library failed: "
                           << ares_strerror(ret), "");
        exit(1);
    }

    // 2. Init Resolver
    res_init();

    // 3. Init name servers
    initNameServers();
}

Cache::~Cache() {
    ares_library_cleanup();
}

void Cache::queryFromCache(const skullcpp::Service& service,
                           const std::string& domain,
                           RDnsRecordVec& rRecords) const {
    auto it = this->records_.find(domain);
    if (it == this->records_.end()) {
        return;
    }

    // Reture the 1st unexpired record
    const DnsRecords& records = it->second;
    size_t nrec = records.records_.size();
    if (!nrec) {
        return;
    }

    time_t now = time(NULL);

    for (const auto& record : records.records_) {
        struct in_addr addr = record.ipaddr;
        int ttl = record.ttl;

        if (now - records.start_ >= ttl) {
            continue;
        }

        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &addr, ip, IPV4_MAX_LENGTH);

        int newTTL = ttl - (int)(now - records.start_);
        rDnsRecord rRecord;
        rRecord.ip  = ip;
        rRecord.ttl = newTTL;
        rRecords.push_back(rRecord);
    }

    //// If not found, create a nopending job to query dns, then return the 1st one
    //auto queryDomain = std::make_shared<std::string>(domain);
    //service.createJob(0, 0, skull_BindSvcJobNPW(_refresh_domain_records, queryDomain), NULL);

    //char ip [IPV4_MAX_LENGTH];
    //inet_ntop(AF_INET, &records.records_[0], ip, IPV4_MAX_LENGTH);
    //return std::string(ip);
}

bool Cache::queryFromDNS(const skullcpp::Service& service,
                         const std::string& domain, bool updateOnly) const {
    // Create a simple internet query for ipv4 address and recursion is desired
    unsigned char* query = NULL;
    int query_len = 0;

    // To backward compatible, here we use `ares_mkquery`, if your
    //  platform support higher version of ares, then recommend to use
    //  `ares_create_query`
    int ret = ares_mkquery(domain.c_str(),
                           ns_c_in,     // Internet class
                           ns_t_a,      // ipv4 address
                           0,           // identifier
                           1,           // recursion is desired
                           &query,
                           &query_len);

    if (ret != ARES_SUCCESS) {
        SKULLCPP_LOG_ERROR("svc.dns.query-2", "create dns query failed: "
            << ares_strerror(ret), "Check whether queried domain is correct");
        ares_free_string(query);
        return false;
    }

    // Create EPClient to send the query string to DNS server
    skullcpp::EPClient epClient;
    epClient.setType(skullcpp::EPClient::UDP);
    epClient.setIP(getNameServerIP());
    epClient.setPort(53);
    epClient.setTimeout(1000);
    epClient.setUnpack(_dns_reply_unpack);

    auto queryDomain = std::make_shared<std::string>(domain);
    auto epCb = updateOnly
                    ? skull_BindEpCb(_ep_cb_updateonly, queryDomain)
                    : skull_BindEpCb(_ep_cb, queryDomain);

    skullcpp::EPClient::Status st =
        epClient.send(service, query, (size_t)query_len, epCb);

    ares_free_string(query);
    if (st != skullcpp::EPClient::Status::OK) {
        return false;
    } else {
        return true;
    }
}

void Cache::updateCache(skullcpp::Service& service, const std::string& domain,
                        DnsRecords& newRecords) {
    auto it = this->records_.find(domain);
    if (it == this->records_.end()) {
        this->records_.insert(std::make_pair(domain, newRecords));
        return;
    }

    DnsRecords& oldRecords = it->second;
    if (newRecords.start_ > oldRecords.start_) {
        this->records_.erase(it);
        this->records_.insert(std::make_pair(domain, newRecords));
    }
}

void Cache::initNameServers() {
    if (_res.nscount == 0) {
        SKULLCPP_LOG_FATAL("Init", "Not found any name server, exit", "");
        exit(1);
    }

    for (int i = 0; i < _res.nscount; i++) {
        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &_res.nsaddr_list[i].sin_addr, ip, IPV4_MAX_LENGTH);

        SKULLCPP_LOG_INFO("Init", "init name server: " << ip << std::endl)
        this->nservers_.push_back(ip);
    }
}

const std::string& Cache::getNameServerIP() const {
    return this->nservers_[0];
}

} // End of namespace

