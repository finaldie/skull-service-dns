#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>
#include <iostream>
#include <google/protobuf/message.h>

#include <skullcpp/api.h>
#include "skull_protos.h"
#include "config.h"
#include "cache.h"

using namespace skull::service::dns;

// ====================== Service Init/Release =================================
static
int  skull_service_init(skullcpp::Service& service, const skull_config_t* config)
{
    skullcpp::Config::instance().load(config);

    // 2. Init Cache
    adns::Cache* dnsCache = new adns::Cache();
    service.set(dnsCache);
    return 0;
}

static
void skull_service_release(skullcpp::Service& service)
{
}

// ====================== Service APIs Calls ===================================
static
void skull_service_query(const skullcpp::Service& service,
                         const google::protobuf::Message& request,
                         google::protobuf::Message& response)
{
    SKULLCPP_LOG_DEBUG("service api: query");

    const adns::Cache* dnsCache = (const adns::Cache*)service.get();
    auto& queryReq  = (const query_req&)request;
    auto& queryResp = (query_resp&)response;

    adns::Cache::QType qtype = queryReq.qtype() == 1
        ? adns::Cache::QType::A : adns::Cache::QType::AAAA;

    // Try query it from cache first
    adns::Cache::RDnsRecordVec records;
    dnsCache->queryFromCache(service, queryReq.question(), qtype, records);

    if (records.empty()) {
        SKULLCPP_LOG_INFO("QueryCache", "Question not found in cache: "
                          << queryReq.question() << " "
                          << "Will query it from dns servers");
    } else {
        queryResp.set_code(0);

        for (auto& record : records) {
            auto* ret = queryResp.add_record();
            ret->set_ip(record.ip);
            ret->set_ttl(record.ttl);
        }

        return;
    }

    // Try query it from DNS
    bool res = dnsCache->queryFromDNS(service, queryReq.question(), qtype);
    if (!res) {
        SKULLCPP_LOG_ERROR("svc.dns.query-3", "dns query from dns failed",
                        "Check whether the name server is correct");
        queryResp.set_code(1);
        queryResp.set_error("query dns error");
    }
}

// ====================== Register Service =====================================
static skullcpp::ServiceReadApi api_read_tbl[] = {
    {"query", skull_service_query},
    {NULL, NULL}
};

static skullcpp::ServiceEntry service_entry = {
    skull_service_init,
    skull_service_release,
    api_read_tbl,
    NULL
};

SKULLCPP_SERVICE_REGISTER(&service_entry)
