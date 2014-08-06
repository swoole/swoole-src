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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"

typedef struct
{
    unsigned short id;
    unsigned short flag;
    unsigned short questions;
    unsigned short answerRRs;
    unsigned short authorityRRs;
    unsigned short additionalRRs;
} DNS_PKG_HEADER, *DNS_PKG_HEADER_PTR;

typedef struct
{
    unsigned char * dns_name;
    unsigned short dns_type;
    unsigned short dns_class;
} DNS_PKG_QUERY, *DNS_PKG_QUERY_PTR;

typedef struct
{
    unsigned short dns_name;
    unsigned short dns_type;
    unsigned short dns_class;
    unsigned short dns_ttl;
    unsigned char* data;
} DNS_RESPONSE_ANSWER, *DNS_RESPONSE_ANSWER_PTR;


int swDNS_resolve(const char* domain, char* ip, unsigned short id)
{
    int result = SW_FALSE;

    DNS_PKG_HEADER_PTR nphp;
    DNS_PKG_QUERY_PTR dkqp;

    char dnsBuff[1024];
    char dnsRecv[2048];

    int send_size = swDNS_send_request(domain, nphp, dkqp, dnsBuff, id);
    if (send_size < 0)
    {

        return SW_ERR;
    }
    swClient cli;
    if (swClient_create(&cli, SW_SOCK_UDP, 1) < 0)
    {
        return SW_ERR;
    }
    struct sockaddr_in server_addr;
    unsigned int pkg_len = 0;
    bzero(&server_addr, sizeof(struct sockaddr_in));
    int server_id  = id % DNS_SERVERS;
    server_addr.sin_family = AF_INET;
        inet_aton(DNS_ADDR, &server_addr.sin_addr);
        server_addr.sin_port = htons(DNS_PORT);
        pkg_len = sizeof(server_addr);
        int in_len = sendto(sockfd, dnsBuff, sizeof(dnsBuff), 0,
                (struct sockaddr*) &server_addr, pkg_len);
        if (in_len < 0)
        {
            std::cout << "tiny dns:ERROR sendto" << strerror(errno)<<std::endl;
            close(sockfd);
            return false;
        }
        int recv_len = 0;
        // if time is out , try again (3 times totally)
//      for (int i = 0; i < 3 && recv_len == 0; i++)
            recv_len = recvfromTimeOut(sockfd, 0, 10000000);//wait 10 seconds
        if (recv_len == 0 || recv_len < 0) {
            // if in_len == 0 stands for timeout, if -1 stands for error
            strncpy(dnscache._domain, domain, 256);
            dnscache._ip[0] = '/0';
            close(sockfd);
            return false;
        }
        else
        {
            //select returns fd it must be sockfd, because only sockfd is selected;
            recv_len = recvfrom(sockfd, dnsRecv, sizeof(dnsRecv), 0,
                    (struct sockaddr*) &server_addr, &pkg_len);
            if (recv_len < 0) {
                std::cout << "tiny dns:ERROR recvfrom" << std::endl;
                strncpy(dnscache._domain, domain, 256);
                dnscache._ip[0] = '/0';
                close(sockfd);
                return false;
            }
            result = recvAnalyse(dnsRecv, recv_len, send_size, ip);
            if (result)
            {
                strncpy(dnscache._domain, domain, 256);
                if(strcmp(ip, "125.211.213.133") == 0){
                    result = false;
                    dnscache._ip[0] = '/0';
                }
                else{
                    strncpy(dnscache._ip, ip, 16);
                }
            }
        }
        close(sockfd);
        return result;

}

int swDNS_send_request(const char* domain, DNS_PKG_HEADER_PTR *nphp, DNS_PKG_QUERY_PTR *dkqp, unsigned char* dnsBuff,
        unsigned short id)
{
    char tmpBuf[256];
    bzero(tmpBuf, 256);
    int domainLen = strlen(domain);
    if (domainLen <= 0)
        return -1;
    memcpy(tmpBuf, domain, domainLen);
    dkqp->dns_name = sw_malloc(domainLen + 2 * sizeof(unsigned char));
    bzero(dkqp->dns_name, domainLen + 2 * sizeof(unsigned char));
    char* tok = NULL;
    tok = strtok(tmpBuf, ".");
    unsigned char dot = '/0';
    int offset = 0;
    while (tok != NULL)
    {
        dot = (unsigned char) strlen(tok);
        memcpy(dkqp->dns_name + offset, &dot, sizeof(unsigned char));
        offset += sizeof(unsigned char);
        memcpy(dkqp->dns_name + offset, tok, strlen(tok));
        offset += strlen(tok);
        tok = strtok(NULL, ".");
    }
    dkqp->dns_name[domainLen + 2 * sizeof(unsigned char) - 1] = 0x00;
    nphp->id = htons(id); //dns transaction id, given randomly
    nphp->flag = htons(0x0100); //dns standard query;
    nphp->questions = htons(0x0001); //num of questions;
    nphp->answerRRs = htons(0x0000);
    nphp->authorityRRs = htons(0x0000);
    nphp->additionalRRs = htons(0x0000);
    dkqp->dns_type = htons(0x0001); //Type   : A
    dkqp->dns_class = htons(0x0001); //Class : IN
    memcpy(dnsBuff, (unsigned char*) nphp, sizeof(DNS_PKG_HEADER));
    memcpy(dnsBuff + sizeof(DNS_PKG_HEADER), (unsigned char*) dkqp->dns_name, domainLen + 2 * sizeof(unsigned char));
    memcpy(dnsBuff + sizeof(DNS_PKG_HEADER) + (domainLen + 2 * sizeof(unsigned char)), (unsigned char*) &dkqp->dns_type,
            sizeof(unsigned short));
    memcpy(dnsBuff + sizeof(DNS_PKG_HEADER) + (domainLen + 2 * sizeof(unsigned char)) + sizeof(unsigned short),
            (unsigned char*) &dkqp->dns_class, sizeof(unsigned short));
    sw_free(dkqp->dns_name);
    return sizeof(DNS_PKG_HEADER) + (domainLen + 2 * sizeof(unsigned char)) + sizeof(unsigned short)
            + sizeof(unsigned short);
}

int swDNS_recvAnalyse(unsigned char* buf, size_t buf_size, size_t send_size, char* ip)
{
    int result = SW_FALSE;
    unsigned char* p = buf;
    p += 2; //dns id
    unsigned short flag = ntohs(*((unsigned short*) p)); // p[0] * 0x100 + p[1];

    if (flag != 0x8180)
    {
        printf("not a \"standard query response no error\"!\n");
        return SW_ERR;
    }
    p += 2; //dns flag
    p += 2; //dns questions
    unsigned short answerRRs = ntohs(*((unsigned short*) p)); //p[0] * 0x100 + p[1];//dns answer RRs
    p = buf + send_size; //p point to Answers
    unsigned short type;
    unsigned short dataLen;
    for (int i = 0; i < answerRRs; i++)
    {
        p += 2; //Name
        type = ntohs(*((unsigned short*) p)); //p[0] * 0x100 + p[1];
        p += 2; //Type;
        if (type == 0x0001)
        {
            p += 2; //Class
            p += 4; //TTL
            p += 2; //Data Length
            strncpy(ip, inet_ntoa(*(struct in_addr*) p), 16);
            result = SW_OK;
            break;
        }
        p += 2; //Class
        p += 4; //TTL
        dataLen = ntohs(*((unsigned short*) p)); //p[0] * 0x100 + p[1];
        p += 2; //Data Length
        p += dataLen; //data
    }
    return result;
}

