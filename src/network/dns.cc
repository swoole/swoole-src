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

#include "swoole.h"
#include "swoole_coroutine_socket.h"
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

bool swoole_load_resolv_conf() {
    FILE *fp;
    char line[100];
    char buf[16] = {};

    if ((fp = fopen(SwooleG.dns_resolvconf_path.c_str(), "rt")) == nullptr) {
        swoole_sys_warning("fopen(%s) failed", SwooleG.dns_resolvconf_path.c_str());
        return false;
    }

    while (fgets(line, 100, fp)) {
        if (strncmp(line, "nameserver", 10) == 0) {
            strcpy(buf, strtok(line, " "));
            strcpy(buf, strtok(nullptr, "\n"));
            break;
        }
    }
    fclose(fp);

    if (strlen(buf) == 0) {
        return false;
    }
    swoole_set_dns_server(buf);
    return true;
}

void swoole_set_hosts_path(const std::string &hosts_file) {
    SwooleG.dns_hosts_path = hosts_file;
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

/* Struct for the flags for the DNS RRs */
struct RR_FLAGS {
    uint16_t type;
    uint16_t rdclass;
    uint32_t ttl;
    uint16_t rdlength;
};

static uint16_t dns_request_id = 1;

static int domain_encode(const char *src, int n, char *dest);
static void domain_decode(char *str);
static std::string parse_ip_address(void *vaddr, int type);

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

static std::string parse_ip_address(void *vaddr, int type) {
    auto addr = reinterpret_cast<unsigned char *>(vaddr);
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
    char *_domain_name;
    Q_FLAGS *qflags = nullptr;
    char packet[SW_BUFFER_SIZE_STD];
    RecordHeader *header = nullptr;
    int steps = 0;
    std::vector<std::string> result;

    if (SwooleG.dns_server_host.empty() && !swoole_load_resolv_conf()) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_NO_SERVER);
        return result;
    }

    header = (RecordHeader *) packet;
    int _request_id = dns_request_id++;
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

    _domain_name = &packet[steps];

    int len = strlen(domain);
    if (domain_encode(domain, len, _domain_name) < 0) {
        swoole_warning("invalid domain[%s]", domain);
        return result;
    }

    steps += (strlen((const char *) _domain_name) + 1);

    qflags = (Q_FLAGS *) &packet[steps];
    qflags->qtype = htons(family == AF_INET6 ? SW_DNS_AAAA_RECORD : SW_DNS_A_RECORD);
    qflags->qclass = htons(0x0001);
    steps += sizeof(Q_FLAGS);

    Socket _sock(SW_SOCK_UDP);
    if (timeout > 0) {
        _sock.set_timeout(timeout);
    }
    if (!_sock.sendto(SwooleG.dns_server_host, SwooleG.dns_server_port, (char *) packet, steps)) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    /**
     * response
     */
    header = nullptr;
    qflags = nullptr;
    RR_FLAGS *rrflags = nullptr;

    uchar rdata[10][254];
    uint32_t type[10];
    sw_memset_zero(rdata, sizeof(rdata));

    char *temp;
    steps = 0;

    char name[10][254];
    int i, j;

    auto ret = _sock.recv(packet, sizeof(packet) - 1);
    if (ret <= 0) {
        swoole_set_last_error(_sock.errCode == ECANCELED ? SW_ERROR_CO_CANCELED : SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }

    packet[ret] = 0;
    header = (RecordHeader *) packet;
    steps = sizeof(RecordHeader);

    _domain_name = &packet[steps];
    domain_decode(_domain_name);
    steps = steps + (strlen(_domain_name) + 2);

    qflags = (Q_FLAGS *) &packet[steps];
    (void) qflags;
    steps = steps + sizeof(Q_FLAGS);

    int ancount = ntohs(header->ancount);
    if (ancount > 10) {
        ancount = 10;
    }
    /* Parsing the RRs from the reply packet */
    for (i = 0; i < ancount; ++i) {
        type[i] = 0;
        /* Parsing the NAME portion of the RR */
        temp = &packet[steps];
        j = 0;
        while (*temp != 0) {
            if ((uchar)(*temp) == 0xc0) {
                ++temp;
                temp = &packet[(uint8_t) *temp];
            } else {
                name[i][j] = *temp;
                ++j;
                ++temp;
            }
        }
        name[i][j] = '\0';

        domain_decode(name[i]);
        steps = steps + 2;

        /* Parsing the RR flags of the RR */
        rrflags = (RR_FLAGS *) &packet[steps];
        steps = steps + sizeof(RR_FLAGS) - 2;

        /* Parsing the IPv4 address in the RR */
        type[i] = ntohs(rrflags->type);
        for (j = 0; j < ntohs(rrflags->rdlength); ++j) {
            rdata[i][j] = (uchar) packet[steps + j];
        }

        /* Parsing the canonical name in the RR */
        if (ntohs(rrflags->type) == 5) {
            temp = &packet[steps];
            j = 0;
            while (*temp != 0) {
                if ((uchar)(*temp) == 0xc0) {
                    ++temp;
                    temp = &packet[(uint8_t) *temp];
                } else {
                    rdata[i][j] = *temp;
                    ++j;
                    ++temp;
                }
            }
            rdata[i][j] = '\0';
            domain_decode((char *) rdata[i]);
            type[i] = ntohs(rrflags->type);
        }
        steps = steps + ntohs(rrflags->rdlength);
    }

    int request_id = ntohs(header->id);
    // bad response
    if (request_id != _request_id) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        return result;
    }
    for (i = 0; i < ancount; i++) {
        if (type[i] != SW_DNS_A_RECORD && type[i] != SW_DNS_AAAA_RECORD) {
            continue;
        }
        result.push_back(parse_ip_address(rdata[i], type[i] == SW_DNS_A_RECORD ? AF_INET : AF_INET6));
    }
    if (result.empty()) {
        swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    }
    return result;
}

/**
 * The function converts the dot-based hostname into the DNS format
 * (i.e. www.apple.com into 3www5apple3com0)
 */
static int domain_encode(const char *src, int n, char *dest) {
    if (src[n] == '.') {
        return SW_ERR;
    }

    int pos = 0;
    int i;
    int len = 0;
    memcpy(dest + 1, src, n + 1);
    dest[n + 1] = '.';
    dest[n + 2] = 0;
    src = dest + 1;
    n++;

    for (i = 0; i < n; i++) {
        if (src[i] == '.') {
            len = i - pos;
            dest[pos] = len;
            pos += len + 1;
        }
    }
    dest[pos] = 0;
    return SW_OK;
}

/**
 * This function converts a DNS-based hostname into dot-based format
 * (i.e. 3www5apple3com0 into www.apple.com)
 */
static void domain_decode(char *str) {
    size_t i, j;
    for (i = 0; i < strlen(str); i++) {
        uint32_t len = str[i];
        for (j = 0; j < len; j++) {
            str[i] = str[i + 1];
            i++;
        }
        str[i] = '.';
    }
    str[i - 1] = '\0';
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
    if (!swoole_event_isset_handler(SW_FD_CARES)) {
        ares_library_init(ARES_LIB_INIT_ALL);
        swoole_event_set_handler(SW_FD_CARES | SW_EVENT_READ, [](Reactor *reactor, Event *event) -> int {
            auto ctx = reinterpret_cast<ResolvContext *>(event->socket->object);
            swoole_trace_log(SW_TRACE_CARES, "[event callback] readable event, fd=%d", event->socket->fd);
            ares_process_fd(ctx->channel, event->fd, ARES_SOCKET_BAD);
            return SW_OK;
        });
        swoole_event_set_handler(SW_FD_CARES | SW_EVENT_WRITE, [](Reactor *reactor, Event *event) -> int {
            auto ctx = reinterpret_cast<ResolvContext *>(event->socket->object);
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
        auto ctx = reinterpret_cast<ResolvContext *>(arg);
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
                _socket->fd = -1;
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

    if (!SwooleG.dns_server_host.empty()) {
#if (ARES_VERSION >= 0x010b00)
        struct ares_addr_port_node servers;
        servers.family = AF_INET;
        servers.next = nullptr;
        inet_pton(AF_INET, SwooleG.dns_server_host.c_str(), &servers.addr.addr4);
        servers.tcp_port = 0;
        servers.udp_port = SwooleG.dns_server_port;
        ares_set_servers_ports(ctx.channel, &servers);
#elif (ARES_VERSION >= 0x010701)
        struct ares_addr_node servers;
        servers.family = AF_INET;
        servers.next = nullptr;
        inet_pton(AF_INET, SwooleG.dns_server_host.c_str(), &servers.addr.addr4);
        ares_set_servers(ctx.channel, &servers);
        if (SwooleG.dns_server_port != SW_DNS_SERVER_PORT) {
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
            auto ctx = reinterpret_cast<ResolvContext *>(data);

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
                        Coroutine *co = reinterpret_cast<Coroutine *>(data);
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
    int __af = flags & (~SW_DNS_LOOKUP_RANDOM);
    int index = 0;
    int rc, err;
    int buf_len = 256;
    struct hostent hbuf;
    struct hostent *result;

    char *buf = (char *) sw_malloc(buf_len);
    if (!buf) {
        return SW_ERR;
    }
    memset(buf, 0, buf_len);
    while ((rc = ::gethostbyname2_r(name, __af, &hbuf, buf, buf_len, &result, &err)) == ERANGE) {
        buf_len *= 2;
        char *tmp = (char *) sw_realloc(buf, buf_len);
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
        if (__af == AF_INET) {
            memcpy(addr_list[i].v4, hbuf.h_addr_list[i], hbuf.h_length);
        } else {
            memcpy(addr_list[i].v6, hbuf.h_addr_list[i], hbuf.h_length);
        }
    }
    if (__af == AF_INET) {
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
    if (!(host_entry = ::gethostbyname2(name, __af))) {
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

int getaddrinfo(GetaddrinfoRequest *req) {
    struct addrinfo *result = nullptr;
    struct addrinfo *ptr = nullptr;
    struct addrinfo hints {};

    hints.ai_family = req->family;
    hints.ai_socktype = req->socktype;
    hints.ai_protocol = req->protocol;

    int ret = ::getaddrinfo(req->hostname, req->service, &hints, &result);
    if (ret != 0) {
        req->error = ret;
        return SW_ERR;
    }

    void *buffer = req->result;
    int i = 0;
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        switch (ptr->ai_family) {
        case AF_INET:
            memcpy((char *) buffer + (i * sizeof(struct sockaddr_in)), ptr->ai_addr, sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            memcpy((char *) buffer + (i * sizeof(struct sockaddr_in6)), ptr->ai_addr, sizeof(struct sockaddr_in6));
            break;
        default:
            swoole_warning("unknown socket family[%d]", ptr->ai_family);
            break;
        }
        i++;
        if (i == SW_DNS_HOST_BUFFER_SIZE) {
            break;
        }
    }
    ::freeaddrinfo(result);
    req->error = 0;
    req->count = i;
    return SW_OK;
}

void GetaddrinfoRequest::parse_result(std::vector<std::string> &retval) {
    struct sockaddr_in *addr_v4;
    struct sockaddr_in6 *addr_v6;

    char tmp[INET6_ADDRSTRLEN];
    const char *r;

    for (int i = 0; i < count; i++) {
        if (family == AF_INET) {
            addr_v4 = (struct sockaddr_in *) ((char *) result + (i * sizeof(struct sockaddr_in)));
            r = inet_ntop(AF_INET, (const void *) &addr_v4->sin_addr, tmp, sizeof(tmp));
        } else {
            addr_v6 = (struct sockaddr_in6 *) ((char *) result + (i * sizeof(struct sockaddr_in6)));
            r = inet_ntop(AF_INET6, (const void *) &addr_v6->sin6_addr, tmp, sizeof(tmp));
        }
        if (r) {
            retval.push_back(tmp);
        }
    }
}
}  // namespace network
}  // namespace swoole
