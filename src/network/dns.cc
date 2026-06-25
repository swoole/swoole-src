/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "swoole_coroutine_socket.h"
#include "swoole_coroutine_system.h"
#include "swoole_coroutine_api.h"
#include "swoole_util.h"

#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <fstream>

#define SW_PATH_HOSTS "/etc/hosts"

#ifdef SW_USE_CARES
#include <ares.h>
#endif

using swoole::NameResolver;
using swoole::coroutine::System;
using swoole::network::Address;

SW_API bool swoole_load_resolv_conf() {
#ifdef _WIN32
    FIXED_INFO *fixed_info = nullptr;
    ULONG buf_len = 0;

    if (GetNetworkParams(fixed_info, &buf_len) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }

    fixed_info = (FIXED_INFO *) malloc(buf_len);
    if (fixed_info == nullptr) {
        return false;
    }

    if (GetNetworkParams(fixed_info, &buf_len) == NO_ERROR) {
        if (fixed_info->DnsServerList.IpAddress.String[0] != '\0') {
            swoole_set_dns_server(fixed_info->DnsServerList.IpAddress.String);
            free(fixed_info);
            return true;
        }
    }

    free(fixed_info);
    return false;
#else
    std::ifstream file(SwooleG.dns_resolvconf_path);
    std::string dns_server_host;

    if (!file.is_open()) {
        swoole_sys_warning("fopen(%s) failed", SwooleG.dns_resolvconf_path.c_str());
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream stream(line);
        std::string key;
        std::string value;

        stream >> key;
        if (key == "nameserver" && stream >> value) {
            dns_server_host = value;
            break;
        }
    }

    if (sw_unlikely(dns_server_host.empty())) {
        return false;
    }
    swoole_set_dns_server(dns_server_host);
    return true;
#endif
}

SW_API void swoole_set_dns_server(const std::string &server) {
    char *_port;
    int dns_server_port = SW_DNS_SERVER_PORT;
    char dns_server_host[32];
    swoole_strlcpy(dns_server_host, server.c_str(), sizeof(dns_server_host));
    if ((_port = strchr(const_cast<char *>(server.c_str()), ':'))) {
        dns_server_port = sw_atoi(_port + 1);
        if (!Address::verify_port(dns_server_port, true)) {
            dns_server_port = SW_DNS_SERVER_PORT;
        }
        dns_server_host[_port - server.c_str()] = '\0';
    }
    SwooleG.dns_server.host = dns_server_host;
    SwooleG.dns_server.port = dns_server_port;
}

SW_API swoole::DnsServer swoole_get_dns_server() {
    if (SwooleG.dns_server.host.empty()) {
        swoole_load_resolv_conf();
    }
    return SwooleG.dns_server;
}

SW_API void swoole_set_hosts_path(const std::string &hosts_file) {
    SwooleG.dns_hosts_path = hosts_file;
}

SW_API void swoole_name_resolver_add(const NameResolver &resolver, bool append) {
    if (append) {
        SwooleG.name_resolvers.push_back(resolver);
    } else {
        SwooleG.name_resolvers.push_front(resolver);
    }
}

SW_API void swoole_name_resolver_each(
    const std::function<swTraverseOperation(const std::list<NameResolver>::iterator &iter)> &fn) {
    for (auto iter = SwooleG.name_resolvers.begin(); iter != SwooleG.name_resolvers.end();) {
        const swTraverseOperation op = fn(iter);
        if (op == SW_TRAVERSE_REMOVE) {
            iter = SwooleG.name_resolvers.erase(iter);
        } else if (op == SW_TRAVERSE_STOP) {
            break;
        } else {
            ++iter;
        }
    }
}

SW_API std::string swoole_name_resolver_lookup(const std::string &host_name, NameResolver::Context *ctx) {
    if (SwooleG.name_resolvers.empty()) {
        goto _dns_lookup;
    }
    for (auto &name_resolver : SwooleG.name_resolvers) {
        std::string result = name_resolver.resolve(host_name, ctx, name_resolver.private_data);
        if (!result.empty() || ctx->final_) {
            return result;
        }
    }
_dns_lookup:
    /*
     * Use DNS to resolve host name by default
     */
    if (swoole_coroutine_is_in()) {
        return System::gethostbyname(host_name, ctx->type, ctx->timeout);
    } else {
        return swoole::network::gethostbyname(ctx->type, host_name);
    }
}

namespace swoole {
namespace coroutine {

enum RecordType {
    SW_DNS_A_RECORD = 0x01,     // Lookup IPv4 address
    SW_DNS_AAAA_RECORD = 0x1c,  // Lookup IPv6 address
    SW_DNS_MX_RECORD = 0x0f     // Lookup mail server for domain
};

enum DNSError {
    SW_DNS_NOT_EXIST,  // Error: address does not exist
    SW_DNS_TIMEOUT,    // Lookup time expired
    SW_DNS_ERROR       // No memory or other error
};

/* Struct for the DNS Header */
struct RecordHeader {
    uint16_t id;
    uchar rd : 1;
    uchar tc : 1;
    uchar aa : 1;
    uchar opcode : 4;
    uchar qr : 1;
    uchar rcode : 4;
    uchar z : 3;
    uchar ra : 1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* Struct for the flags for the DNS Question */
struct Q_FLAGS {
    uint16_t qtype;
    uint16_t qclass;
};

static int domain_encode(const char *src, int n, char *dest, size_t dest_len);
static bool dns_skip_name(const char *packet, size_t packet_len, size_t offset, size_t *consumed);
static bool dns_read_uint16(const char *packet, size_t packet_len, size_t offset, uint16_t *value);
static std::string parse_ip_address(const void *vaddr, int type);

std::string get_ip_by_hosts(const std::string &search_domain) {
    std::ifstream file(SwooleG.dns_hosts_path.empty() ? SW_PATH_HOSTS : SwooleG.dns_hosts_path);
    if (!file.is_open()) {
        return "";
    }

    std::string line;
    std::string domain;
    std::string txtaddr;
    std::vector<std::string> domains;
    std::unordered_map<std::string, std::string> result{};

    while (getline(file, line)) {
        std::string::size_type ops = line.find_first_of('#');
        if (ops != std::string::npos) {
            line[ops] = '\0';
        }

        if (line[0] == '\n' || line[0] == '\0' || line[0] == '\r') {
            continue;
        }

        std::istringstream stream(line);
        while (stream >> domain) {
            domains.push_back(domain);
        }
        if (domains.empty() || domains.size() == 1) {
            domains.clear();
            continue;
        }

        txtaddr = domains[0];
        for (size_t i = 1; i < domains.size(); i++) {
            result.insert(std::make_pair(domains[i], txtaddr));
        }

        auto iter = result.find(search_domain);
        if (iter != result.end()) {
            return iter->second;
        } else {
            result.clear();
            domains.clear();
            continue;
        }
    }

    return "";
}

static std::string parse_ip_address(const void *vaddr, int type) {
    auto addr = static_cast<const unsigned char *>(vaddr);
    std::string ip_addr;
    if (type == AF_INET) {
        char buff[4 * 4 + 3 + 1];
        sw_snprintf(buff, sizeof(buff), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
        return ip_addr.assign(buff);
    } else if (type == AF_INET6) {
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) {
                ip_addr.append(":");
            }
            char buf[4 + 1];
            size_t n = sw_snprintf(buf, sizeof(buf), "%02x%02x", addr[i], addr[i + 1]);
            ip_addr.append(buf, n);
        }
    } else {
        assert(0);
    }
    return ip_addr;
}

std::vector<std::string> dns_lookup_impl_with_socket(const char *domain, int family, double timeout) {
    Q_FLAGS *qflags = nullptr;
    char packet[SW_BUFFER_SIZE_STD];
    RecordHeader *header = nullptr;
    size_t steps = 0;
    std::vector<std::string> result;

    if (SwooleG.dns_server.host.empty() && !swoole_load_resolv_conf()) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_NO_SERVER);
        return result;
    }

    static SW_THREAD_LOCAL uint16_t dns_request_id = 1;
    int _request_id = dns_request_id++;
    if (dns_request_id == 65535) {
    	dns_request_id = 1;
    }

    header = reinterpret_cast<RecordHeader *>(packet);
    header->id = htons(_request_id);
    header->qr = 0;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 0;
    header->z = 0;
    header->rcode = 0;
    header->qdcount = htons(1);
    header->ancount = 0x0000;
    header->nscount = 0x0000;
    header->arcount = 0x0000;

    steps = sizeof(RecordHeader);

    char *_domain_name = &packet[steps];

    const int len = strlen(domain);
    int domain_name_len = domain_encode(domain, len, _domain_name, sizeof(packet) - steps);
    if (domain_name_len < 0) {
        swoole_warning("invalid domain[%s]", domain);
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    steps += domain_name_len;
    if (sw_unlikely(steps + sizeof(Q_FLAGS) > sizeof(packet))) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    qflags = reinterpret_cast<Q_FLAGS *>(&packet[steps]);
    qflags->qtype = htons(family == AF_INET6 ? SW_DNS_AAAA_RECORD : SW_DNS_A_RECORD);
    qflags->qclass = htons(0x0001);
    steps += sizeof(Q_FLAGS);

    Socket _sock(SW_SOCK_UDP);
    if (timeout > 0) {
        _sock.set_timeout(timeout);
    }
    if (!_sock.sendto(SwooleG.dns_server.host, SwooleG.dns_server.port, (char *) packet, steps)) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    /**
     * response
     */
    auto ret = _sock.recv(packet, sizeof(packet) - 1);
    if (ret <= 0) {
        swoole_set_last_error(_sock.errCode == ECANCELED ? SW_ERROR_CO_CANCELED : SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    const size_t packet_len = ret;
    if (sw_unlikely(packet_len < sizeof(RecordHeader))) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    header = reinterpret_cast<RecordHeader *>(packet);
    int request_id = ntohs(header->id);
    if (sw_unlikely(request_id != _request_id)) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    steps = sizeof(RecordHeader);

    const uint16_t qdcount = ntohs(header->qdcount);
    const uint16_t ancount = ntohs(header->ancount);
    for (uint16_t i = 0; i < qdcount; i++) {
        size_t consumed = 0;
        if (sw_unlikely(!dns_skip_name(packet, packet_len, steps, &consumed))) {
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
            return result;
        }
        steps += consumed;
        if (sw_unlikely(steps + sizeof(Q_FLAGS) > packet_len)) {
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
            return result;
        }
        steps += sizeof(Q_FLAGS);
    }

    for (uint16_t i = 0; i < ancount; i++) {
        size_t consumed = 0;
        uint16_t rr_type = 0;
        uint16_t rdlength = 0;

        if (sw_unlikely(!dns_skip_name(packet, packet_len, steps, &consumed))) {
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
            return result;
        }
        steps += consumed;

        // RR fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
        if (sw_unlikely(steps + 10 > packet_len ||
                        !dns_read_uint16(packet, packet_len, steps, &rr_type) ||
                        !dns_read_uint16(packet, packet_len, steps + 8, &rdlength))) {
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
            return result;
        }
        steps += 10;

        if (sw_unlikely(steps + rdlength > packet_len)) {
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
            return result;
        }

        if (rr_type == SW_DNS_A_RECORD) {
            if (sw_unlikely(rdlength != sizeof(in_addr))) {
                swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
                return result;
            }
            result.push_back(parse_ip_address(packet + steps, AF_INET));
        } else if (rr_type == SW_DNS_AAAA_RECORD) {
            if (sw_unlikely(rdlength != sizeof(in6_addr))) {
                swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
                return result;
            }
            result.push_back(parse_ip_address(packet + steps, AF_INET6));
        } else if (rr_type == 5) {
            size_t cname_consumed = 0;
            if (sw_unlikely(!dns_skip_name(packet, packet_len, steps, &cname_consumed) || cname_consumed > rdlength)) {
                swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
                return result;
            }
        }

        steps += rdlength;
        if (result.size() >= 10) {
            break;
        }
    }

    if (result.empty()) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    }
    return result;
}

static bool dns_read_uint16(const char *packet, size_t packet_len, size_t offset, uint16_t *value) {
    if (sw_unlikely(offset + sizeof(uint16_t) > packet_len)) {
        return false;
    }
    uint16_t tmp;
    memcpy(&tmp, packet + offset, sizeof(tmp));
    *value = ntohs(tmp);
    return true;
}

static bool dns_skip_name(const char *packet, size_t packet_len, size_t offset, size_t *consumed) {
    size_t pos = offset;
    size_t read_bytes = 0;
    bool jumped = false;

    *consumed = 0;

    for (size_t depth = 0; depth < packet_len; depth++) {
        if (sw_unlikely(pos >= packet_len)) {
            return false;
        }

        const auto length = static_cast<unsigned char>(packet[pos]);
        const auto label_type = length & 0xc0;

        if (label_type == 0xc0) {
            if (sw_unlikely(pos + 1 >= packet_len)) {
                return false;
            }
            const size_t pointer = ((length & 0x3f) << 8) | static_cast<unsigned char>(packet[pos + 1]);
            if (sw_unlikely(pointer >= packet_len)) {
                return false;
            }
            if (!jumped) {
                read_bytes += 2;
                *consumed = read_bytes;
            }
            jumped = true;
            pos = pointer;
            continue;
        }

        if (sw_unlikely(label_type != 0 || length > 63)) {
            return false;
        }

        pos++;
        if (!jumped) {
            read_bytes++;
        }

        if (length == 0) {
            if (!jumped) {
                *consumed = read_bytes;
            }
            return true;
        }

        if (sw_unlikely(pos + length > packet_len)) {
            return false;
        }
        pos += length;
        if (!jumped) {
            read_bytes += length;
        }
    }

    return false;
}

/**
 * The function converts the dot-based hostname into the DNS format
 * (i.e. www.apple.com into 3www5apple3com0)
 */
static int domain_encode(const char *src, int n, char *dest, size_t dest_len) {
    if (sw_unlikely(n <= 0 || src[n] == '.' || static_cast<size_t>(n) > 253)) {
        return SW_ERR;
    }

    size_t dest_pos = 0;
    size_t label_start = 0;
    const size_t src_len = n;

    for (size_t i = 0; i <= src_len; i++) {
        if (i != src_len && src[i] != '.') {
            continue;
        }

        const size_t label_len = i - label_start;
        if (sw_unlikely(label_len == 0 || label_len > 63 || dest_pos + label_len + 1 >= dest_len)) {
            return SW_ERR;
        }

        dest[dest_pos++] = static_cast<char>(label_len);
        memcpy(dest + dest_pos, src + label_start, label_len);
        dest_pos += label_len;
        label_start = i + 1;
    }

    if (sw_unlikely(dest_pos >= dest_len)) {
        return SW_ERR;
    }
    dest[dest_pos++] = 0;
    return dest_pos;
}

#ifdef SW_USE_CARES
struct ResolvContext {
    ares_channel channel;
    ares_options ares_opts;
    int ares_flags;
    int error;
    bool completed;
    Coroutine *co;
    std::shared_ptr<bool> defer_task_cancelled;
    std::unordered_map<int, network::Socket *> sockets;
    std::vector<std::string> result;
};

std::vector<std::string> dns_lookup_impl_with_cares(const char *domain, int family, double timeout) {
    if (!swoole_event_isset_handler(SW_FD_CARES, SW_EVENT_READ)) {
        ares_library_init(ARES_LIB_INIT_ALL);
        swoole_event_set_handler(SW_FD_CARES, SW_EVENT_READ, [](Reactor *reactor, Event *event) -> int {
            auto ctx = static_cast<ResolvContext *>(event->socket->object);
            swoole_trace_log(SW_TRACE_CARES, "[event callback] readable event, fd=%d", event->socket->fd);
            ares_process_fd(ctx->channel, event->fd, ARES_SOCKET_BAD);
            return SW_OK;
        });
        swoole_event_set_handler(SW_FD_CARES, SW_EVENT_WRITE, [](Reactor *reactor, Event *event) -> int {
            auto ctx = static_cast<ResolvContext *>(event->socket->object);
            swoole_trace_log(SW_TRACE_CARES, "[event callback] writable event, fd=%d", event->socket->fd);
            ares_process_fd(ctx->channel, ARES_SOCKET_BAD, event->fd);
            return SW_OK;
        });
        sw_reactor()->add_destroy_callback([](void *_data) { ares_library_cleanup(); }, nullptr);
    }

    ResolvContext ctx{};
    Coroutine *co = Coroutine::get_current_safe();
    ctx.co = co;
    ctx.completed = false;
    ctx.defer_task_cancelled = std::make_shared<bool>(false);
    char lookups[] = "fb";
    int res;
    ctx.ares_opts.lookups = lookups;
    ctx.ares_opts.timeout = timeout * 1000;
    ctx.ares_opts.tries = SwooleG.dns_tries;
    ctx.ares_opts.sock_state_cb_data = &ctx;
    ctx.ares_opts.sock_state_cb = [](void *arg, int fd, int readable, int writable) {
        auto ctx = static_cast<ResolvContext *>(arg);
        int events = 0;
        if (readable) {
            events |= SW_EVENT_READ;
        }
        if (writable) {
            events |= SW_EVENT_WRITE;
        }

        swoole_trace_log(SW_TRACE_CARES, "[sock_state_cb], fd=%d, readable=%d, writable=%d", fd, readable, writable);

        network::Socket *_socket = nullptr;
        if (ctx->sockets.find(fd) == ctx->sockets.end()) {
            if (events == 0) {
                swoole_warning("error events, fd=%d", fd);
                return;
            }
            _socket = make_socket(fd, SW_FD_CARES);
            _socket->object = ctx;
            ctx->sockets[fd] = _socket;
        } else {
            _socket = ctx->sockets[fd];
            if (events == 0) {
                swoole_trace_log(SW_TRACE_CARES, "[del event], fd=%d", fd);
                swoole_event_del(_socket);
                _socket->fd = SW_BAD_SOCKET;
                _socket->free();
                ctx->sockets.erase(fd);
                return;
            }
        }

        if (_socket->events) {
            swoole_event_set(_socket, events);
            swoole_trace_log(SW_TRACE_CARES, "[set event] fd=%d, events=%d", fd, events);
        } else {
            swoole_event_add(_socket, events);
            swoole_trace_log(SW_TRACE_CARES, "[add event] fd=%d, events=%d", fd, events);
        }
    };
    ctx.ares_flags = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB | ARES_OPT_LOOKUPS;

    if ((res = ares_init_options(&ctx.channel, &ctx.ares_opts, ctx.ares_flags)) != ARES_SUCCESS) {
        swoole_warning("ares_init_options() failed, Error: %s[%d]", ares_strerror(res), res);
        goto _return;
    }

    if (!SwooleG.dns_server.host.empty()) {
#if (ARES_VERSION >= 0x010b00)
        struct ares_addr_port_node servers = {};
        servers.family = AF_INET;
        servers.udp_port = SwooleG.dns_server.port;
        inet_pton(AF_INET, SwooleG.dns_server.host.c_str(), &servers.addr.addr4);
        ares_set_servers_ports(ctx.channel, &servers);
#elif (ARES_VERSION >= 0x010701)
        struct ares_addr_node servers = {};
        servers.family = AF_INET;
        inet_pton(AF_INET, SwooleG.dns_server.host.c_str(), &servers.addr.addr4);
        ares_set_servers(ctx.channel, &servers);
        if (SwooleG.dns_server.port != SW_DNS_SERVER_PORT) {
            swoole_warning("not support to set port of dns server");
        }
#else
        swoole_warning("not support to set dns server");
#endif
    }

    ares_gethostbyname(
        ctx.channel,
        domain,
        family,
        [](void *data, int status, int timeouts, struct hostent *hostent) {
            auto ctx = static_cast<ResolvContext *>(data);

            swoole_trace_log(SW_TRACE_CARES, "[cares callback] status=%d, timeouts=%d", status, timeouts);

            if (timeouts > 0) {
                ctx->error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
                goto _resume;
            }

            if (status != ARES_SUCCESS) {
                ctx->error = status;
                goto _resume;
            }

            if (hostent->h_addr_list) {
                char **paddr = hostent->h_addr_list;
                while (*paddr != nullptr) {
                    ctx->result.emplace_back(parse_ip_address(*paddr, hostent->h_addrtype));
                    paddr++;
                }
            }
        _resume:
            if (ctx->co && ctx->co->is_suspending()) {
                auto _cancelled = ctx->defer_task_cancelled;
                swoole_event_defer(
                    [_cancelled](void *data) {
                        if (*_cancelled) {
                            return;
                        }
                        auto *co = static_cast<Coroutine *>(data);
                        co->resume();
                    },
                    ctx->co);
                ctx->co = nullptr;
            } else {
                ctx->completed = true;
            }
        },
        &ctx);

    if (ctx.error || ctx.completed) {
        goto _destroy;
    }

    co->yield_ex(timeout);
    if (co->is_canceled()) {
        ares_cancel(ctx.channel);
    } else if (co->is_timedout()) {
        ares_process_fd(ctx.channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        ctx.error = ARES_ETIMEOUT;
    } else {
        swoole_trace_log(SW_TRACE_CARES, "lookup success, result_count=%lu", ctx.result.size());
    }
_destroy:
    if (ctx.error) {
        switch (ctx.error) {
        case ARES_ECANCELLED:
            swoole_set_last_error(SW_ERROR_CO_CANCELED);
            break;
        case ARES_ETIMEOUT:
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT);
            break;
        default:
            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
            break;
        }
    }
    *ctx.defer_task_cancelled = true;
    ares_destroy(ctx.channel);
_return:
    return ctx.result;
}
#endif

std::vector<std::string> dns_lookup(const char *domain, int family, double timeout) {
    family = family == AF_INET6 ? AF_INET6 : AF_INET;  // only support IPv4 and IPv6
#ifdef SW_USE_CARES
    return dns_lookup_impl_with_cares(domain, family, timeout);
#else
    return dns_lookup_impl_with_socket(domain, family, timeout);
#endif
}

}  // namespace coroutine

/**
 * blocking-IO, Use in synchronous mode or AIO thread pool
 */
namespace network {

#ifndef HAVE_GETHOSTBYNAME2_R
#include <mutex>
static std::mutex g_gethostbyname2_lock;
#endif

#ifdef HAVE_GETHOSTBYNAME2_R
int gethostbyname(int flags, const char *name, char *addr) {
    int _af = flags & (~SW_DNS_LOOKUP_RANDOM);
    int index = 0;
    int rc, err;
    int buf_len = 256;
    hostent hbuf{};
    hostent *result;

    char *buf = static_cast<char *>(sw_malloc(buf_len));
    if (!buf) {
        return SW_ERR;
    }
    memset(buf, 0, buf_len);
    while ((rc = ::gethostbyname2_r(name, _af, &hbuf, buf, buf_len, &result, &err)) == ERANGE) {
        buf_len *= 2;
        char *tmp = static_cast<char *>(sw_realloc(buf, buf_len));
        if (nullptr == tmp) {
            sw_free(buf);
            return SW_ERR;
        } else {
            buf = tmp;
        }
    }

    if (0 != rc || nullptr == result) {
        sw_free(buf);
        return SW_ERR;
    }

    union {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } addr_list[SW_DNS_HOST_BUFFER_SIZE]{};

    int i = 0;
    for (i = 0; i < SW_DNS_HOST_BUFFER_SIZE; i++) {
        if (hbuf.h_addr_list[i] == nullptr) {
            break;
        }
        if (_af == AF_INET) {
            memcpy(addr_list[i].v4, hbuf.h_addr_list[i], hbuf.h_length);
        } else {
            memcpy(addr_list[i].v6, hbuf.h_addr_list[i], hbuf.h_length);
        }
    }
    if (_af == AF_INET) {
        memcpy(addr, addr_list[index].v4, hbuf.h_length);
    } else {
        memcpy(addr, addr_list[index].v6, hbuf.h_length);
    }

    sw_free(buf);

    return SW_OK;
}
#else
int gethostbyname(int flags, const char *name, char *addr) {
    int __af = flags & (~SW_DNS_LOOKUP_RANDOM);
    int index = 0;

    std::lock_guard<std::mutex> _lock(g_gethostbyname2_lock);

    struct hostent *host_entry;
#ifdef _WIN32
    // Windows does not have gethostbyname2, use gethostbyname for IPv4 only
    if (__af != AF_INET || !(host_entry = ::gethostbyname(name))) {
#else
    if (!(host_entry = ::gethostbyname2(name, __af))) {
#endif
        return SW_ERR;
    }

    union {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } addr_list[SW_DNS_HOST_BUFFER_SIZE];

    int i = 0;
    for (i = 0; i < SW_DNS_HOST_BUFFER_SIZE; i++) {
        if (host_entry->h_addr_list[i] == nullptr) {
            break;
        }
        if (__af == AF_INET) {
            memcpy(addr_list[i].v4, host_entry->h_addr_list[i], host_entry->h_length);
        } else {
            memcpy(addr_list[i].v6, host_entry->h_addr_list[i], host_entry->h_length);
        }
    }
    if (__af == AF_INET) {
        memcpy(addr, addr_list[index].v4, host_entry->h_length);
    } else {
        memcpy(addr, addr_list[index].v6, host_entry->h_length);
    }
    return SW_OK;
}
#endif

std::string gethostbyname(int type, const std::string &name) {
    char addr[sizeof(in6_addr)];
    if (gethostbyname(type, name.c_str(), addr) == SW_OK) {
        return Address::addr_str(type, addr);
    }
    swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    return {};
}

int getaddrinfo(GetaddrinfoRequest *req) {
    addrinfo *result = nullptr;
    addrinfo *ptr = nullptr;
    addrinfo hints{};

    hints.ai_family = req->family;
    hints.ai_socktype = req->socktype;
    hints.ai_protocol = req->protocol;

    int ret = ::getaddrinfo(req->hostname.c_str(), req->service.c_str(), &hints, &result);
    if (sw_unlikely(ret != 0)) {
        req->error = ret;
        return SW_ERR;
    }

    int i = 0;
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next, i++) {
    }
    req->count = SW_MIN(i, SW_DNS_HOST_BUFFER_SIZE);
    req->results.resize(req->count);

    for (ptr = result, i = 0; ptr != nullptr && i < req->count; ptr = ptr->ai_next, i++) {
        switch (ptr->ai_family) {
        case AF_INET:
            memcpy(&req->results[i], ptr->ai_addr, sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            memcpy(&req->results[i], ptr->ai_addr, sizeof(struct sockaddr_in6));
            break;
        default:
            swoole_warning("unknown socket family[%d]", ptr->ai_family);
            break;
        }
    }
    ::freeaddrinfo(result);
    req->error = 0;

    return SW_OK;
}

int gethostbyname(GethostbynameRequest *req) {
    const auto rv = gethostbyname(req->family, req->name);
    if (rv.empty()) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return SW_ERR;
    }
    req->addr = rv;
    return SW_OK;
}
}  // namespace network

void GetaddrinfoRequest::parse_result(std::vector<std::string> &retval) const {
    for (auto &addr : results) {
        const char *addr_str;
        if (family == AF_INET6) {
            addr_str = Address::addr_str(family, &addr.sin6_addr);
        } else {
            addr_str = Address::addr_str(family, &((sockaddr_in *) &addr)->sin_addr);
        }
        if (addr_str) {
            retval.emplace_back(addr_str);
        }
    }
}
}  // namespace swoole
