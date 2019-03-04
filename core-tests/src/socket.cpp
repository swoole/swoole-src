#include "tests.h"
#ifndef _WIN32
TEST(socket, swSocket_unix_sendto)
{
    int fd1,fd2,ret;
    struct sockaddr_un un1,un2;
    char sock1_path[] = "/tmp/udp_unix1.sock";
    char sock2_path[] = "/tmp/udp_unix2.sock";
    char test_data[] = "swoole";

    bzero(&un1,sizeof(struct sockaddr_un));
    bzero(&un2,sizeof(struct sockaddr_un));

    un1.sun_family = AF_UNIX;
    un2.sun_family = AF_UNIX;

    unlink(sock1_path);
    unlink(sock2_path);

    fd1 = socket(AF_UNIX,SOCK_DGRAM,0);
    strncpy(un1.sun_path, sock1_path, sizeof(un1.sun_path) - 1); 
    bind(fd1,(struct sockaddr *)&un1,sizeof(un1));

    fd2 = socket(AF_UNIX,SOCK_DGRAM,0);
    strncpy(un2.sun_path, sock2_path, sizeof(un2.sun_path) - 1); 
    bind(fd2,(struct sockaddr *)&un2,sizeof(un2));

    ret = swSocket_unix_sendto(fd1,sock2_path,test_data,strlen(test_data));
    ASSERT_GT(ret, 0);

    unlink(sock1_path);
    unlink(sock2_path);
}
#endif
