#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <iostream>
#include <google/protobuf/message.h>

#include <skullcpp/api.h>
#include "skull_protos.h"
#include "config.h"
#include "cache.h"

using namespace skull::service::dns;

// ====================== Service Init/Release =================================
static
void skull_service_init(skullcpp::Service& service, const skull_config_t* config)
{
    printf("skull service init\n");

    // 1. Convert skull_config to skull_static_config
    skull_static_config_convert(config);

    // 2. Init Cache
    adns::Cache* dnsCache = new adns::Cache();
    service.set(dnsCache);
}

static
void skull_service_release(skullcpp::Service& service)
{
    skull_static_config_destroy();

    adns::Cache* dnsCache = (adns::Cache*)service.get();
    delete dnsCache;

    printf("skull service release\n");
}

// ====================== Service APIs Calls ===================================
static
void skull_service_query(const skullcpp::Service& service,
                         const google::protobuf::Message& request,
                         google::protobuf::Message& response)
{
    std::cout << "skull service api: query" << std::endl;
    SKULL_LOG_INFO("svc.dns.query-1", "service api: query");

    const adns::Cache* dnsCache = (const adns::Cache*)service.get();
    auto& queryReq = (const query_req&)request;
    auto& queryResp = (query_resp&)response;

    // Try query it from cache first
    const std::string ip = dnsCache->queryFromCache(service, queryReq.domain());

    if (ip.empty()) {
        SKULL_LOG_ERROR("svc.dns.query-2", "dns query from cache failed",
                        "Check whether queried domain is correct");
        printf("dns query from cache failed\n");
    } else {
        queryResp.set_code(0);
        queryResp.set_ip(ip);
        return;
    }

    // Try query it from DNS
    bool res = dnsCache->queryFromDNS(service, queryReq.domain(), false);
    if (!res) {
        SKULL_LOG_ERROR("svc.dns.query-3", "dns query from dns failed",
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
