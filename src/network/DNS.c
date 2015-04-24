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

#define SW_DNS_SERVER_CONF   "/etc/resolv.conf"
#define SW_DNS_SERVER_NUM    2
#define SW_DNS_SERVER_PORT   53

enum swDNS_type
{
    SW_DNS_A_RECORD = 0x01, //Lookup IP address
    SW_DNS_AAAA_RECORD = 0x1c, //Lookup IPv6 address
    SW_DNS_MX_RECORD = 0x0f //Lookup mail server for domain
};

enum swDNS_error
{
    SW_DNS_NOT_EXIST, //Error: adress does not exist
    SW_DNS_TIMEOUT, //Lookup time expired
    SW_DNS_ERROR //No memory or other error
};

typedef struct
{
    int id;
    union
    {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } ipaddr;
} swDNS_server;

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

static swDNS_server swoole_dns_servers[SW_DNS_SERVER_NUM];
static int swoole_dns_server_num = 0;
static int swoole_dns_request_id = 1;
static void* swoole_dns_request_ptr[1024];

static void swDNSResolver_domain_encode(char *src, char *dest);
static void swDNSResolver_domain_decode(char *str);
static int swDNSResolver_get_servers(swDNS_server *dns_server);
static int swDNSResolver_onReceive(swReactor *reactor, swEvent *event);

static int swDNSResolver_get_servers(swDNS_server *dns_server)
{
    FILE *fp;
    char line[100];
    swoole_dns_server_num = 0;

    if ((fp = fopen(SW_DNS_SERVER_CONF, "rt")) == NULL)
    {
        swWarn("fopen("SW_DNS_SERVER_CONF") failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

    while (fgets(line, 100, fp))
    {
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strcpy(dns_server[swoole_dns_server_num].ipaddr.v4, strtok(line, " "));
            strcpy(dns_server[swoole_dns_server_num].ipaddr.v4, strtok(NULL, "\n"));
            swoole_dns_server_num++;
        }
        if (swoole_dns_server_num >= SW_DNS_SERVER_NUM)
        {
            break;
        }
    }

    if (swoole_dns_server_num == 0)
    {
        return SW_ERR;
    }
    fclose(fp);
    return SW_OK;
}

static int swDNSResolver_onReceive(swReactor *reactor, swEvent *event)
{
    swDNSResolver_header *header = NULL;
    swClient *cli;
    Q_FLAGS *qflags = NULL;
    RR_FLAGS *rrflags = NULL;

    char packet[65536];
    char rdata[10][254];
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
    swDNSResolver_domain_decode(_domain_name);
    steps = steps + (strlen(_domain_name) + 2);

    qflags = (Q_FLAGS *) &packet[steps];
    steps = steps + sizeof(Q_FLAGS);

    //printf("ancount=%d, nscount=%d, qdcount=%d, arcount=%d\n", ntohs(header->ancount), ntohs(header->nscount), ntohs(header->qdcount), ntohs(header->arcount));

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
                temp = &packet[*temp];
            }
            else
            {
                name[i][j] = *temp;
                ++j;
                ++temp;
            }
        }
        name[i][j] = '\0';

        swDNSResolver_domain_decode(name[i]);
        steps = steps + 2;

        /* Parsing the RR flags of the RR */
        rrflags = (RR_FLAGS *) &packet[steps];
        steps = steps + sizeof(RR_FLAGS) - 2;

        /* Parsing the IPv4 address in the RR */
        if (ntohs(rrflags->type) == 1)
        {
            for (j = 0; j < ntohs(rrflags->rdlength); ++j)
                rdata[i][j] = (uchar) packet[steps + j];
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
                    temp = &packet[*temp];
                }
                else
                {
                    rdata[i][j] = *temp;
                    ++j;
                    ++temp;
                }
            }
            rdata[i][j] = '\0';
            swDNSResolver_domain_decode(rdata[i]);
            type[i] = ntohs(rrflags->type);
        }
        steps = steps + ntohs(rrflags->rdlength);
    }

    /* Printing the output */
    printf("QNAME: %s\n", _domain_name);
    printf("ANCOUNT: %d\n", ntohs(header->ancount));
    printf("\nRDATA:");

    for (i = 0; i < ntohs(header->ancount); ++i)
    {
        printf("\nNAME: %s\n\t", name[i]);
        if (type[i] == 5)
            printf("CNAME: %s", rdata[i]);
        else if (type[i] == 1)
        {
            printf("IPv4: ");
            for (j = 0; j < ntohs(rrflags->rdlength); ++j)
                printf("%d.", rdata[i][j]);
            printf("\b ");
        }
    }
    putchar('\n');
    return SW_OK;
}

int swDNSResolver_request(swDNS_request *request)
{
    char *_domain_name;
    Q_FLAGS *qflags = NULL;
    char packet[65536];
    swDNSResolver_header *header = NULL;
    int i, j, steps = 0;

    if (swoole_dns_server_num == 0)
    {
        if (swDNSResolver_get_servers(swoole_dns_servers) < 0)
        {
            return SW_ERR;
        }
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_DNS_RESOLVER, swDNSResolver_onReceive);
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
    swDNSResolver_domain_encode(request->domain, _domain_name);

    steps += (strlen((const char *) _domain_name) + 1);

    qflags = (Q_FLAGS *) &packet[steps];
    qflags->qtype = htons(SW_DNS_A_RECORD);
    qflags->qclass = htons(0x0001);
    steps += sizeof(Q_FLAGS);

    swClient *cli = sw_malloc(sizeof(swClient));
    if (cli == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    if (swClient_create(cli, SW_SOCK_UDP, 0) < 0)
    {
        return SW_ERR;
    }
    if (cli->connect(cli, swoole_dns_servers[0].ipaddr.v4, SW_DNS_SERVER_PORT, 1, 0) < 0)
    {
        cli->close(cli);
        return SW_ERR;
    }
    if (cli->send(cli, (char *) packet, steps) < 0)
    {
        cli->close(cli);
        return SW_ERR;
    }
    if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, SW_FD_DNS_RESOLVER))
    {
        cli->close(cli);
        return SW_ERR;
    }
    cli->ptr = request;
    swoole_dns_request_ptr[swoole_dns_request_id] = cli;
    swoole_dns_request_id++;
    return SW_OK;
}

/**
 * The function converts the dot-based hostname into the DNS format
 * (i.e. www.apple.com into 3www5apple3com0)
 */
static void swDNSResolver_domain_encode(char *src, char *dest)
{
    int pos = 0;
    int len = 0;
    int n = strlen(src);
    int i;
    strcat(src, ".");

    for (i = 0; i < n; ++i)
    {
        if (src[i] == '.')
        {
            dest[pos] = i - len;
            ++pos;
            for (; len < i; ++len)
            {
                dest[pos] = src[len];
                ++pos;
            }
            len++;
        }
    }
    dest[pos] = '\0';
}

/**
 * This function converts a DNS-based hostname into dot-based format
 * (i.e. 3www5apple3com0 into www.apple.com)
 */
static void swDNSResolver_domain_decode(char *str)
{
    int i, j;
    for (i = 0; i < strlen((const char*) str); ++i)
    {
        unsigned int len = str[i];
        for (j = 0; j < len; ++j)
        {
            str[i] = str[i + 1];
            ++i;
        }
        str[i] = '.';
    }
    str[i - 1] = '\0';
}
