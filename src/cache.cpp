#include <stdlib.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <ares.h>

#include <iostream>
#include <memory>

#include "cache.h"
#include "config.h"
#include "skull_protos.h"

using namespace skull::service::dns;

#define MAX_DNS_REPLY_ADDRS 100
#define DNS_NS              "SKULL_DNS_NS"

// ====================== Internal Functions ===================================
class UpdateJobdata {
private:
    std::string domain_;
    adns::Cache::QType qtype;
    adns::Cache::DnsRecords records_;

public:
    UpdateJobdata(const std::string& domain, adns::Cache::QType qtype) {
        this->domain_ = domain;
        this->qtype   = qtype;
        this->records_.start_ = time(NULL);
    }

    void append(const adns::Cache::RDnsRecord& record) {
        this->records_.records_.push_back(record);
    }

    const std::string& domain() const {
        return this->domain_;
    }

    adns::Cache::QType queryType() const {
        return this->qtype;
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
    adns::Cache::QType qtype  = jobData->queryType();
    adns::Cache::DnsRecords& records = jobData->records();

    dnsCache->updateCache(service, domain, qtype, records);
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
void _dns_resp_cb(const skullcpp::Service& service, skullcpp::EPClientRet& ret,
            std::shared_ptr<std::string>& domain, adns::Cache::QType qtype)
{
    // 1. Prepare and validate ep status
    SKULLCPP_LOG_DEBUG("dns_resp_cb: response len: " << ret.responseSize()
                       << ", status: " << ret.status()
                       << ", latency: " << ret.latency());

    auto& apiData   = ret.apiData();
    auto& queryReq  = (const query_req&)apiData.request();
    auto& queryResp = (query_resp&)apiData.response();

    if (ret.status() != skullcpp::EPClient::Status::OK) {
        SKULLCPP_LOG_ERROR("svc.dns.query-3",
            "Dns query failed due to network issue: " << *domain
            << ", status: " << ret.status(),
            "Check network or dns server status");

        queryResp.set_code(1);
        queryResp.set_error("Dns query failed");
        return;
    }

    // 2. Parse dns answers
    int naddrs = MAX_DNS_REPLY_ADDRS;
    struct ares_addrttl addrs[MAX_DNS_REPLY_ADDRS];
    memset(addrs, 0, sizeof(struct ares_addrttl) * MAX_DNS_REPLY_ADDRS);
    const auto* response = (const unsigned char *)ret.response();

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
    }

    SKULLCPP_LOG_DEBUG("Got " << naddrs << " dns records");

    if (!naddrs) {
        queryResp.set_code(1);
        queryResp.set_error("Dns query failed, no ip returned");
        return;
    }

    // 3. Fill the api response
    queryResp.set_code(0);
    auto jobData = std::make_shared<UpdateJobdata>(queryReq.question(), qtype);

    for (int i = 0; i < naddrs; i++) {
        // 1. Fill jobData for updating the cache
        char ip [INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addrs[i].ipaddr, ip, INET_ADDRSTRLEN);

        adns::Cache::RDnsRecord rRecord;
        rRecord.ip = ip;
        rRecord.ttl = addrs[i].ttl;

        jobData->append(rRecord);

        SKULLCPP_LOG_DEBUG(" - ip: " << ip << "; ttl: " << addrs[i].ttl);

        // 2. Fill the service response
        auto* record = queryResp.add_record();
        record->set_ip(ip);
        record->set_ttl(addrs[i].ttl);
    }

    // 4. Update it via a service job
    service.createJob(0, -1, skull_BindSvcJobNPW(_dnsrecord_updating, jobData), NULL);
}

static
void _dns6_resp_cb(const skullcpp::Service& service, skullcpp::EPClientRet& ret,
            std::shared_ptr<std::string>& domain, adns::Cache::QType qtype)
{
    // 1. Prepare and validate ep status
    SKULLCPP_LOG_DEBUG("dns6_resp_cb: response len: " << ret.responseSize()
                       << ", status: " << ret.status()
                       << ", latency: " << ret.latency());

    auto& apiData   = ret.apiData();
    auto& queryReq  = (const query_req&)apiData.request();
    auto& queryResp = (query_resp&)apiData.response();

    if (ret.status() != skullcpp::EPClient::Status::OK) {
        SKULLCPP_LOG_ERROR("svc.dns6.query-3",
            "Dns query failed due to network issue: " << *domain
            << ", status: " << ret.status(),
            "Check network or dns server status");

        queryResp.set_code(1);
        queryResp.set_error("Dns query failed");
        return;
    }

    // 2. Parse dns answers
    int naddrs = MAX_DNS_REPLY_ADDRS;
    struct ares_addr6ttl addrs[MAX_DNS_REPLY_ADDRS];
    memset(addrs, 0, sizeof(struct ares_addr6ttl) * MAX_DNS_REPLY_ADDRS);
    const auto* response = (const unsigned char *)ret.response();

    int r = ares_parse_aaaa_reply(response, (int)ret.responseSize(),
                                  NULL, addrs, &naddrs);

    if (r != ARES_SUCCESS) {
        SKULLCPP_LOG_ERROR("svc.dns6.query-4", "dns parse reply failed: "
            << ares_strerror(r)
            << " domain: " << queryReq.question(),
            "Check whether queried domain is correct");

        queryResp.set_code(1);
        queryResp.set_error("Dns6 query failed, check whether domain is correct");
        return;
    }

    SKULLCPP_LOG_DEBUG("Got " << naddrs << " dns AAAA records");

    if (!naddrs) {
        queryResp.set_code(1);
        queryResp.set_error("Dns query failed, no ip returned");
        return;
    }

    // 3. Fill the api response
    queryResp.set_code(0);
    auto jobData = std::make_shared<UpdateJobdata>(queryReq.question(), qtype);

    for (int i = 0; i < naddrs; i++) {
        // 1. Fill jobData for updating the cache
        char ip [INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addrs[i].ip6addr, ip, INET6_ADDRSTRLEN);

        adns::Cache::RDnsRecord rRecord;
        rRecord.ip = ip;
        rRecord.ttl = addrs[i].ttl;

        jobData->append(rRecord);

        SKULLCPP_LOG_DEBUG(" - ip: " << ip << "; ttl: " << addrs[i].ttl);

        // 2. Fill the service response
        auto* record = queryResp.add_record();
        record->set_ip(ip);
        record->set_ttl(addrs[i].ttl);
    }

    // 4. Update it via a service job
    service.createJob(0, -1, skull_BindSvcJobNPW(_dnsrecord_updating, jobData), NULL);
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
                           QType qtype,
                           RDnsRecordVec& rRecords) const {
    auto* cache = &this->recordsA_;

    if (qtype == QType::AAAA) {
        cache = &this->records4A_;
    }

    auto it = cache->find(domain);
    if (it == cache->end()) {
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
        const auto& ip = record.ip;
        int ttl = record.ttl;

        if (now - records.start_ >= ttl) {
            continue;
        }

        int newTTL = ttl - (int)(now - records.start_);
        RDnsRecord rRecord;
        rRecord.ip  = ip;
        rRecord.ttl = newTTL;
        rRecords.push_back(rRecord);
    }
}

bool Cache::queryFromDNS(const skullcpp::Service& service,
                         const std::string& question, QType qtype) const {
    // Create a simple internet query for ipv4 address and recursion is desired
    unsigned char* query = NULL;
    int query_len = 0;
    __ns_type type = qtype == QType::A ? ns_t_a : ns_t_aaaa;
    SKULLCPP_LOG_DEBUG("Got question: " << question << ", "
                       << "qtype: " << qtype);

    // To backward compatible, here we use `ares_mkquery`, if your
    //  platform support higher version of ares, then recommend to use
    //  `ares_create_query`
    int ret = ares_mkquery(question.c_str(),
                           ns_c_in,     // Internet class
                           type,        // A or AAAA
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
    const auto& conf = skullcpp::Config::instance();
    SKULLCPP_LOG_DEBUG("conf.query_timeout: " << conf.query_timeout());

    skullcpp::EPClient epClient;
    epClient.setType(skullcpp::EPClient::UDP);
    epClient.setIP(getNameServerIP());
    epClient.setPort(53);
    epClient.setTimeout(conf.query_timeout());
    epClient.setUnpack(_dns_reply_unpack);

    auto queryDomain = std::make_shared<std::string>(question);
    auto epCb = qtype == QType::A
            ? skull_BindEpCb(_dns_resp_cb,  queryDomain, qtype)
            : skull_BindEpCb(_dns6_resp_cb, queryDomain, qtype);

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
                        QType qtype, DnsRecords& newRecords) {
    auto* cache = &this->recordsA_;

    if (qtype == QType::AAAA) {
        cache = &this->records4A_;
    }

    auto it = cache->find(domain);
    if (it == cache->end()) {
        cache->insert(std::make_pair(domain, newRecords));
        return;
    }

    DnsRecords& oldRecords = it->second;
    if (newRecords.start_ > oldRecords.start_) {
        cache->erase(it);
        cache->insert(std::make_pair(domain, newRecords));
    }
}

void Cache::initNameServers() {
    // If ENV 'SKULL_DNS_NS' has value, will push this one into first record
    const char* ns = getenv(DNS_NS);
    if (ns) {
        SKULLCPP_LOG_INFO("Init", "Init name server from ENV: " << ns << std::endl)
        this->nservers_.push_back(ns);
    }

    // If resolv.conf has nameservers, then push them into list
    if (_res.nscount == 0) {
        SKULLCPP_LOG_WARN("Init", "Not found any name server from resolv.conf", "");
    } else {
        for (int i = 0; i < _res.nscount; i++) {
            char ip [INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &_res.nsaddr_list[i].sin_addr, ip, INET_ADDRSTRLEN);

            SKULLCPP_LOG_INFO("Init", "Init name server from resolv.conf: "
                              << ip << std::endl)

            this->nservers_.push_back(ip);
        }
    }

    if (this->nservers_.empty()) {
        SKULLCPP_LOG_FATAL("Init", "Not found any name server",
                           "Check resolv.conf whether correct or define a ENV var");
        exit(1);
    }
}

const std::string& Cache::getNameServerIP() const {
    return this->nservers_[0];
}

} // End of namespace

