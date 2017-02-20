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
#include "Client.h"

#define SW_DNS_SERVER_CONF         "/etc/resolv.conf"
#define SW_DNS_SERVER_NUM          2

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

typedef struct
{
    void (*callback)(char *domain, swDNSResolver_result *result, void *data);
    char *domain;
    void *data;
} swDNS_lookup_request;

typedef struct
{
    uint8_t num;

} swDNS_result;

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
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} RR_FLAGS;

static int swoole_dns_request_id = 1;
static swClient *resolver_socket = NULL;
static swHashMap *request_map = NULL;

static int domain_encode(char *src, int n, char *dest);
static void domain_decode(char *str);
static int swDNSResolver_get_server();
static int swDNSResolver_onReceive(swReactor *reactor, swEvent *event);

static int swDNSResolver_get_server()
{
    FILE *fp;
    char line[100];
    char buf[16];

    if ((fp = fopen(SW_DNS_SERVER_CONF, "rt")) == NULL)
    {
        swWarn("fopen("SW_DNS_SERVER_CONF") failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    while (fgets(line, 100, fp))
    {
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strcpy(buf, strtok(line, " "));
            strcpy(buf, strtok(NULL, "\n"));
            break;
        }
    }
    fclose(fp);
    SwooleG.dns_server_v4 = strdup(buf);
    return SW_OK;
}

static int swDNSResolver_onReceive(swReactor *reactor, swEvent *event)
{
    swDNSResolver_header *header = NULL;
    Q_FLAGS *qflags = NULL;
    RR_FLAGS *rrflags = NULL;

    char packet[65536];
    uchar rdata[10][254];
    uint32_t type[10];

    char *temp;
    uint16_t steps;

    char *_domain_name;
    char name[10][254];
    int i, j;

    if (recv(event->fd, packet, 65536, 0) <= 0)
    {
        //cli->close(cli);
        return SW_ERR;
    }

    header = (swDNSResolver_header *) &packet;
    steps = sizeof(swDNSResolver_header);

    _domain_name = &packet[steps];
    domain_decode(_domain_name);
    steps = steps + (strlen(_domain_name) + 2);

    qflags = (Q_FLAGS *) &packet[steps];
    (void) qflags;
    steps = steps + sizeof(Q_FLAGS);

    /* Parsing the RRs from the reply packet */
    for (i = 0; i < ntohs(header->ancount); ++i)
    {
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
                if ((uchar)(*temp) == 0xc0)
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
    swDNS_lookup_request *request = swHashMap_find_int(request_map, request_id);
    if (request == NULL)
    {
        swWarn("bad response, request_id=%d.", request_id);
        return SW_OK;
    }

    swDNSResolver_result result;
    bzero(&result, sizeof(result));

    for (i = 0; i < ntohs(header->ancount); ++i)
    {
        if (type[i] != SW_DNS_A_RECORD)
        {
            continue;
        }
        j = result.num;
        result.num++;
        result.hosts[j].length = sprintf(result.hosts[j].address, "%d.%d.%d.%d", rdata[i][0], rdata[i][1], rdata[i][2], rdata[i][3]);
        if (result.num == SW_DNS_HOST_BUFFER_SIZE)
        {
            break;
        }
    }

    request->callback(request->domain, &result, request->data);
    swHashMap_del_int(request_map, request_id);
    sw_strdup_free(request->domain);
    sw_free(request);

    return SW_OK;
}

int swDNSResolver_request(char *domain, void (*callback)(char *, swDNSResolver_result *, void *), void *data)
{
    char *_domain_name;
    Q_FLAGS *qflags = NULL;
    char packet[8192];
    swDNSResolver_header *header = NULL;
    int steps = 0;

    if (SwooleG.dns_server_v4 == NULL)
    {
        if (swDNSResolver_get_server() < 0)
        {
            return SW_ERR;
        }
    }

    header = (swDNSResolver_header *) &packet;
    header->id = (uint16_t) htons(swoole_dns_request_id);
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

    swDNS_lookup_request *request = sw_malloc(sizeof(swDNS_lookup_request));
    if (request == NULL)
    {
        swWarn("malloc(%d) failed.", (int ) sizeof(swDNS_lookup_request));
        return SW_ERR;
    }

    int len = strlen(domain);
    request->domain = strndup(domain, len + 1);
    if (request->domain == NULL)
    {
        swWarn("strdup(%d) failed.", len + 1);
        return SW_ERR;
    }

    request->data = data;
    request->callback = callback;

    if (domain_encode(request->domain, len, _domain_name) < 0)
    {
        swWarn("invalid domain[%s].", domain);
        return SW_ERR;
    }

    steps += (strlen((const char *) _domain_name) + 1);

    qflags = (Q_FLAGS *) &packet[steps];
    qflags->qtype = htons(SW_DNS_A_RECORD);
    qflags->qclass = htons(0x0001);
    steps += sizeof(Q_FLAGS);

    if (resolver_socket == NULL)
    {
        resolver_socket = sw_malloc(sizeof(swClient));
        if (resolver_socket == NULL)
        {
            swWarn("malloc failed.");
            return SW_ERR;
        }
        if (swClient_create(resolver_socket, SW_SOCK_UDP, 0) < 0)
        {
            return SW_ERR;
        }
        if (resolver_socket->connect(resolver_socket, SwooleG.dns_server_v4, SW_DNS_SERVER_PORT, 1, 0) < 0)
        {
            resolver_socket->close(resolver_socket);
            return SW_ERR;
        }
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_DNS_RESOLVER, swDNSResolver_onReceive);
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, resolver_socket->socket->fd, SW_FD_DNS_RESOLVER))
        {
            resolver_socket->close(resolver_socket);
            return SW_ERR;
        }
    }

    if (resolver_socket->send(resolver_socket, (char *) packet, steps, 0) < 0)
    {
        resolver_socket->close(resolver_socket);
        swClient_free(resolver_socket);
        sw_free(resolver_socket);
        resolver_socket = NULL;
        return SW_ERR;
    }

    if (!request_map)
    {
        request_map = swHashMap_new(128, NULL);
    }
    swHashMap_add_int(request_map, swoole_dns_request_id, request);
    swoole_dns_request_id++;
    return SW_OK;
}

/**
 * The function converts the dot-based hostname into the DNS format
 * (i.e. www.apple.com into 3www5apple3com0)
 */
static int domain_encode(char *src, int n, char *dest)
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
    int i, j;
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
