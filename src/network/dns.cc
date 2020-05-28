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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "coroutine_socket.h"
#include <string>
#include <vector>

#define SW_DNS_SERVER_CONF         "/etc/resolv.conf"
#define SW_DNS_SERVER_NUM          2

using namespace swoole::coroutine;
using namespace std;

enum swDNS_type
{
    SW_DNS_A_RECORD    = 0x01, //Lookup IPv4 address
    SW_DNS_AAAA_RECORD = 0x1c, //Lookup IPv6 address
    SW_DNS_MX_RECORD   = 0x0f  //Lookup mail server for domain
};

enum swDNS_error
{
    SW_DNS_NOT_EXIST, //Error: adress does not exist
    SW_DNS_TIMEOUT,   //Lookup time expired
    SW_DNS_ERROR      //No memory or other error
};

/* Struct for the DNS Header */
typedef struct
{
    uint16_t id;
    uchar rd :1;
    uchar tc :1;
    uchar aa :1;
    uchar opcode :4;
    uchar qr :1;
    uchar rcode :4;
    uchar z :3;
    uchar ra :1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} swDNSResolver_header;

/* Struct for the flags for the DNS Question */
typedef struct q_flags
{
    uint16_t qtype;
    uint16_t qclass;
} Q_FLAGS;

/* Struct for the flags for the DNS RRs */
typedef struct rr_flags
{
    uint16_t type;
    uint16_t rdclass;
    uint32_t ttl;
    uint16_t rdlength;
} RR_FLAGS;

static uint16_t swoole_dns_request_id = 1;

static int domain_encode(const char *src, int n, char *dest);
static void domain_decode(char *str);
static int get_dns_server();

static int get_dns_server()
{
    FILE *fp;
    char line[100];
    char buf[16] = {};

    if ((fp = fopen(SW_DNS_SERVER_CONF, "rt")) == nullptr)
    {
        swSysWarn("fopen(" SW_DNS_SERVER_CONF ") failed");
        return SW_ERR;
    }

    while (fgets(line, 100, fp))
    {
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strcpy(buf, strtok(line, " "));
            strcpy(buf, strtok(nullptr, "\n"));
            break;
        }
    }
    fclose(fp);

    if (strlen(buf) == 0)
    {
        SwooleG.dns_server_v4 = sw_strdup(SW_DNS_DEFAULT_SERVER);
    }
    else
    {
        SwooleG.dns_server_v4 = sw_strdup(buf);
    }

    return SW_OK;
}

vector<string> swoole::coroutine::dns_lookup(const char *domain, double timeout)
{
    char *_domain_name;
    Q_FLAGS *qflags = nullptr;
    char packet[SW_BUFFER_SIZE_STD];
    swDNSResolver_header *header = nullptr;
    int steps = 0;

    vector<string> result;
    if (SwooleG.dns_server_v4 == nullptr)
    {
        if (get_dns_server() < 0)
        {
            return result;
        }
    }

    header = (swDNSResolver_header *) packet;
    int _request_id = swoole_dns_request_id++;
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

    steps = sizeof(swDNSResolver_header);

    _domain_name = &packet[steps];

    int len = strlen(domain);
    if (domain_encode(domain, len, _domain_name) < 0)
    {
        swWarn("invalid domain[%s]", domain);
        return result;
    }

    steps += (strlen((const char *) _domain_name) + 1);

    qflags = (Q_FLAGS *) &packet[steps];
    qflags->qtype = htons(SW_DNS_A_RECORD);
    qflags->qclass = htons(0x0001);
    steps += sizeof(Q_FLAGS);

    Socket _sock(SW_SOCK_UDP);
    if (timeout > 0)
    {
        _sock.set_timeout(timeout);
    }

    char *_port;
    int dns_server_port = SW_DNS_SERVER_PORT;
    char dns_server_host[32];
    strcpy(dns_server_host, SwooleG.dns_server_v4);
    if ((_port = strchr(SwooleG.dns_server_v4, ':')))
    {
        dns_server_port = atoi(_port + 1);
        dns_server_host[_port - SwooleG.dns_server_v4] = '\0';
    }
    if (!_sock.sendto(dns_server_host, dns_server_port, (char *) packet, steps))
    {
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

    char *temp;
    steps = 0;

    char name[10][254];
    int i, j;

    int ret = _sock.recv(packet, sizeof(packet) - 1);
    if (ret <= 0)
    {
        return result;
    }

    packet[ret] = 0;
    header = (swDNSResolver_header *) packet;
    steps = sizeof(swDNSResolver_header);

    _domain_name = &packet[steps];
    domain_decode(_domain_name);
    steps = steps + (strlen(_domain_name) + 2);

    qflags = (Q_FLAGS *) &packet[steps];
    (void) qflags;
    steps = steps + sizeof(Q_FLAGS);

    int ancount = ntohs(header->ancount);
    if (ancount > 10)
    {
        ancount = 10;
    }
    /* Parsing the RRs from the reply packet */
    for (i = 0; i < ancount; ++i)
    {
        type[i] = 0;
        /* Parsing the NAME portion of the RR */
        temp = &packet[steps];
        j = 0;
        while (*temp != 0)
        {
            if ((uchar) (*temp) == 0xc0)
            {
                ++temp;
                temp = &packet[(uint8_t) *temp];
            }
            else
            {
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
        if (ntohs(rrflags->type) == 1)
        {
            for (j = 0; j < ntohs(rrflags->rdlength); ++j)
            {
                rdata[i][j] = (uchar) packet[steps + j];
            }
            type[i] = ntohs(rrflags->type);
        }

        /* Parsing the canonical name in the RR */
        if (ntohs(rrflags->type) == 5)
        {
            temp = &packet[steps];
            j = 0;
            while (*temp != 0)
            {
                if ((uchar) (*temp) == 0xc0)
                {
                    ++temp;
                    temp = &packet[(uint8_t) *temp];
                }
                else
                {
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
    //bad response
    if (request_id != _request_id)
    {
        return result;
    }
    for (i = 0; i < ancount; i++)
    {
        if (type[i] != SW_DNS_A_RECORD)
        {
            continue;
        }
        char address[16];
        size_t n = sw_snprintf(address, sizeof(address), "%d.%d.%d.%d", rdata[i][0], rdata[i][1], rdata[i][2],
                rdata[i][3]);
        result.push_back(string(address, n));
    }
    return result;
}

/**
 * The function converts the dot-based hostname into the DNS format
 * (i.e. www.apple.com into 3www5apple3com0)
 */
static int domain_encode(const char *src, int n, char *dest)
{
    if (src[n] == '.')
    {
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

    for (i = 0; i < n; i++)
    {
        if (src[i] == '.')
        {
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
static void domain_decode(char *str)
{
    size_t i, j;
    for (i = 0; i < strlen((const char*) str); i++)
    {
        unsigned int len = str[i];
        for (j = 0; j < len; j++)
        {
            str[i] = str[i + 1];
            i++;
        }
        str[i] = '.';
    }
    str[i - 1] = '\0';
}
