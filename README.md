# skull-service-dns
This is an example of skull service for building a Async DNS client.

----
## Main Features:
- [x] Fully Async DNS Query
- [x] Implemented a simple local cache(not LRU)
- [x] Support loading /etc/resolv.conf
- [ ]  Support loading /etc/hosts
- [ ]  Build a LRU cache

## How to use it?
1. cd $project_root/src/services
1. git clone $this_repo dns
1. Use `skull service --import dns` to load this into your skull project

## Screen Output
```console
module(test): init
skull service init
skull service init
init name server: 192.168.31.1
module_unpack(test): data sz:6
receive data: asdf

ServiceCall ret: 0
skull service api: query
dns query from cache failed
ep dns _unpack len: 59
dns _ep_cb: response len: 59, status: 0, latency: 62
got 1dns replies
 - ip: 172.217.2.36; ttl: 63
dns query result:
return ip: 172.217.2.36
_dnsrecord_updating done, domain: www.google.com
module_pack(test): data sz:6


module_unpack(test): data sz:9
receive data: aaaaaaa

ServiceCall ret: 0
skull service api: query
Try to find a valid ip, ttl: 63
dns query result:
return ip: 172.217.2.36
module_pack(test): data sz:9
```
