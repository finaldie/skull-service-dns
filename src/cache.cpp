#include <stdlib.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <iostream>
#include <memory>

#include "cache.h"
#include "skull_protos.h"

using namespace skull::service::dns;

#define MAX_DNS_REPLY_ADDRS 10
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
    std::cout << "_dnsrecord_updating done, domain: " << domain << std::endl;
}

// dns callback functions
static
size_t _dns_reply_unpack(const void* data, size_t len)
{
    std::cout << "ep dns _unpack len: " << len << std::endl;
    return len;
}

static
void _ep_cb(const skullcpp::Service& service, skullcpp::EPClientRet& ret,
            std::shared_ptr<std::string>& domain)
{
    // 1. Prepare and validate ep status
    std::cout << "dns _ep_cb: response len: " << ret.responseSize()
              << ", status: " << ret.status()
              << ", latency: " << ret.latency()
              << std::endl;

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
        std::cout << "dns parse reply failed: " << ares_strerror(r) << std::endl;

        SKULLCPP_LOG_ERROR("svc.dns.query-4", "dns parse reply failed: "
            << ares_strerror(r)
            << " domain: " << queryReq.domain(),
            "Check whether queried domain is correct");

        queryResp.set_code(1);
        queryResp.set_error("Dns query failed, check whether domain is correct");

        return;
    }

    std::cout << "got " << naddrs << "dns replies" << std::endl;
    if (!naddrs) {
        queryResp.set_code(1);
        queryResp.set_error("Dns query failed, no ip returned");
        return;
    }

    // 3. Fill the api response
    queryResp.set_code(0);
    bool filled = false;
    auto jobData = std::make_shared<UpdateJobdata>(queryReq.domain());

    for (int i = 0; i < naddrs; i++) {
        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &addrs[i].ipaddr, ip, IPV4_MAX_LENGTH);
        printf(" - ip: %s; ttl: %d\n", ip, addrs[i].ttl);
        jobData->append(addrs[i]);

        if (!filled) {
            // Fill ip
            queryResp.set_ip(ip);
            filled = true;
        }
    }

    // 4. Update it via a service job
    service.createJob(0, 0, skull_BindSvc(_dnsrecord_updating, jobData));
}

static
void _ep_cb_updateonly(const skullcpp::Service& service,
                       skullcpp::EPClientRet& ret,
                       std::shared_ptr<std::string>& domain)
{
    // 1. Prepare and validate ep status
    std::cout << "dns _ep_cb_updateonly: response len: " << ret.responseSize()
              << ", status: " << ret.status()
              << ", latency: " << ret.latency()
              << std::endl;

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
        std::cout << "dns parse reply failed: " << ares_strerror(r) << std::endl;

        SKULLCPP_LOG_ERROR("svc.dns.query-4", "dns parse reply failed: "
            << ares_strerror(r)
            << " domain: " << domain,
            "Check whether queried domain is correct");
        return;
    }

    std::cout << "got " << naddrs << "dns replies" << std::endl;
    if (!naddrs) {
        return;
    }

    // 3. Fill the api response
    auto jobData = std::make_shared<UpdateJobdata>(*domain);

    for (int i = 0; i < naddrs; i++) {
        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &addrs[i].ipaddr, ip, IPV4_MAX_LENGTH);
        printf(" - ip: %s; ttl: %d\n", ip, addrs[i].ttl);
        jobData->append(addrs[i]);
    }

    // 4. Update it via a service job
    service.createJob(0, 0, skull_BindSvc(_dnsrecord_updating, jobData));
}

static
void _refresh_domain_records(skullcpp::Service& service,
                             const std::shared_ptr<std::string>& domain) {
    auto dnsCache = (adns::Cache*)service.get();

    bool ret = dnsCache->queryFromDNS(service, *domain, true);
    if (!ret) {
        std::cout << "_refresh_domain_records: query domain failed" << std::endl;
    } else {
        std::cout << "_refresh_domain_records: query domain success" << std::endl;
    }
}

namespace adns {

Cache::Cache() {
    // 1. Init ares library
    int ret = ares_library_init(ARES_LIB_INIT_ALL);
    if (ret) {
        printf("Init ares library failed: %s\n", ares_strerror(ret));
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

const std::string Cache::queryFromCache(const skullcpp::Service& service,
                                        const std::string& domain) const {
    auto it = this->records_.find(domain);
    if (it == this->records_.end()) {
        return "";
    }

    // Reture the 1st unexpired record
    const DnsRecords& records = it->second;
    size_t nrec = records.records_.size();
    if (!nrec) {
        return "";
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
        return std::string(ip);
    }

    // If not found, create a job to query dns, then return the 1st one
    auto queryDomain = std::make_shared<std::string>(domain);
    service.createJob(0, 0, skull_BindSvc(_refresh_domain_records, queryDomain));

    char ip [IPV4_MAX_LENGTH];
    inet_ntop(AF_INET, &records.records_[0], ip, IPV4_MAX_LENGTH);
    return std::string(ip);
}

bool Cache::queryFromDNS(const skullcpp::Service& service,
                      const std::string& domain, bool updateOnly) const {
    // Create a simple internet query for ipv4 address and recursion is desired
    unsigned char* query = NULL;
    int query_len = 0;

    int ret = ares_create_query(domain.c_str(),
                                ns_c_in,     // Internet class
                                ns_t_a,      // ipv4 address
                                0,           // identifier
                                1,           // recursion is desired
                                &query,
                                &query_len,
                                65535);

    if (ret != ARES_SUCCESS) {
        SKULLCPP_LOG_ERROR("svc.dns.query-2", "create dns query failed: "
            << ares_strerror(ret), "Check whether queried domain is correct");
        std::cout << "create dns query failed: " << ares_strerror(ret) << std::endl;
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
                    ? skull_BindEp(_ep_cb_updateonly, queryDomain)
                    : skull_BindEp(_ep_cb, queryDomain);

    skullcpp::EPClient::Status st = epClient.send(service, query,
                                        (size_t)query_len,
                                        epCb);
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
        std::cout << "Not found any name server, exit" << std::endl;
        exit(1);
    }

    for (int i = 0; i < _res.nscount; i++) {
        char ip [IPV4_MAX_LENGTH];
        inet_ntop(AF_INET, &_res.nsaddr_list[i].sin_addr, ip, IPV4_MAX_LENGTH);

        std::cout << "init name server: " << ip << std::endl;
        this->nservers_.push_back(ip);
    }
}

const std::string& Cache::getNameServerIP() const {
    return this->nservers_[0];
}

} // End of namespace

