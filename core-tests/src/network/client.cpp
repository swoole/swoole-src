#include "test_core.h"
#include "test_server.h"
#include "test_process.h"
#include "core-tests/include/test_core.h"

#include <random>
#include <iomanip>
#include <sstream>

#define GREETER "Hello Swoole"
#define GREETER_SIZE sizeof(GREETER)

using swoole::HttpProxy;
using swoole::Mutex;
using swoole::Pipe;
using swoole::Socks5Proxy;
using swoole::String;
using swoole::network::Address;
using swoole::network::AsyncClient;
using swoole::network::Client;
using swoole::network::Socket;
using swoole::network::SyncClient;
using swoole::test::Process;
using swoole::test::Server;

TEST(client, tcp) {
    int ret;
    char buf[128];

    pid_t pid;
    int port = swoole::test::get_random_port();

    Process proc([port](Process *proc) {
        Server serv(TEST_HOST, port, swoole::Server::MODE_BASE, SW_SOCK_TCP);
        serv.on("Receive", [](ON_RECEIVE_PARAMS) {
            SERVER_THIS->send(req->info.fd, req->data, req->info.len);
            return 0;
        });
        serv.start();
    });

    pid = proc.start();

    usleep(300000);  // wait for the test server to start

    Client cli(SW_SOCK_TCP, false);
    ASSERT_NE(cli.socket, nullptr);
    ret = cli.connect(TEST_HOST, port, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);

    Address peer_name;
    ASSERT_EQ(cli.get_peer_name(&peer_name), 0);
    ASSERT_STREQ(peer_name.get_addr(), "127.0.0.1");
    ASSERT_EQ(peer_name.get_port(), port);

    ASSERT_EQ(cli.close(), SW_OK);
    ASSERT_EQ(cli.close(), SW_ERR);

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

static void test_sync_client_dgram(const char *host, int port, enum swSocketType type) {
    int ret;
    char buf[128];
    pid_t pid;

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    Process proc([&](Process *proc) {
        Server serv(host, port, swoole::Server::MODE_BASE, type);
        serv.on("Packet", [](ON_PACKET_PARAMS) -> int {
            swoole::DgramPacket *packet = (swoole::DgramPacket *) req->data;
            SERVER_THIS->sendto(packet->socket_addr, packet->data, packet->length, req->info.server_fd);
            return 0;
        });
        serv.on("Start", [lock](ON_START_PARAMS) { lock->unlock(); });
        serv.start();
    });

    pid = proc.start();

    lock->lock();

    Client cli(type, false);
    ASSERT_NE(cli.socket, nullptr);
    ret = cli.connect(host, port, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(client, udp) {
    int port = swoole::test::get_random_port();
    test_sync_client_dgram("127.0.0.1", port, SW_SOCK_UDP);
}

TEST(client, udp6) {
    int port = swoole::test::get_random_port();
    test_sync_client_dgram("::1", port, SW_SOCK_UDP6);
}

TEST(client, udg) {
    test_sync_client_dgram("/tmp/swoole_core_tests.sock", 0, SW_SOCK_UNIX_DGRAM);
}

static void test_async_client_tcp(const char *host, int port, enum swSocketType type) {
    pid_t pid;
    Pipe p(true);
    ASSERT_TRUE(p.ready());

    Process proc([&](Process *proc) {
        Server serv(Socket::is_inet6(type) ? TEST_HOST6 : TEST_HOST, port, swoole::Server::MODE_BASE, type);

        serv.set_private_data("pipe", &p);

        serv.on("Receive", [](ON_RECEIVE_PARAMS) {
            SERVER_THIS->send(req->info.fd, req->data, req->info.len);
            return 0;
        });

        serv.on("WorkerStart", [](ON_WORKER_START_PARAMS) {
            Pipe *p = (Pipe *) SERVER_THIS->get_private_data("pipe");
            int64_t value = 1;
            p->write(&value, sizeof(value));
        });

        serv.start();
    });

    pid = proc.start();
    int64_t value;
    p.set_timeout(10);
    p.read(&value, sizeof(value));

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    AsyncClient ac(type);

    ac.on_connect([](AsyncClient *ac) { ac->send(SW_STRS(GREETER)); });

    ac.on_close([](AsyncClient *ac) {});
    ac.on_error([](AsyncClient *ac) {});

    ac.on_receive([](AsyncClient *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    });

    bool retval = ac.connect(host, port, 1.0);
    EXPECT_TRUE(retval);

    swoole_event_wait();

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(client, async_tcp) {
    test_async_client_tcp(TEST_HOST, swoole::test::get_random_port(), SW_SOCK_TCP);
}

TEST(client, async_tcp_dns) {
    test_async_client_tcp("localhost", swoole::test::get_random_port(), SW_SOCK_TCP);
}

TEST(client, async_tcp6) {
    test_async_client_tcp("::1", swoole::test::get_random_port(), SW_SOCK_TCP6);
}

TEST(client, async_tcp6_dns) {
    test_async_client_tcp("localhost", swoole::test::get_random_port(), SW_SOCK_TCP6);
}

TEST(client, async_tcp_dns_fail) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Client ac(SW_SOCK_TCP, true);

    ASSERT_EQ(ac.connect(TEST_HOST, 9999), SW_ERR);

    bool success = true;

    ac.onConnect = [&success](Client *ac) {
        ac->send(SW_STRS(GREETER));
        success = true;
    };

    ac.onClose = [](Client *ac) {};

    ac.onError = [&success](Client *ac) {
        DEBUG() << "connect failed, ERROR: " << errno << "\n";
        ASSERT_ERREQ(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
        success = false;
    };

    ac.onReceive = [](Client *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    };

    ASSERT_EQ(ac.connect("www.baidu.com-not-found", 80, 1.0), SW_OK);

    swoole_event_wait();

    ASSERT_FALSE(success);
}

TEST(client, async_tcp_ssl_handshake_fail) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Client ac(SW_SOCK_TCP, true);

    bool success = true;

    ac.onConnect = [&success](Client *ac) {
        ac->send(SW_STRS(GREETER));
        success = true;
    };

    ac.onClose = [](Client *ac) {};

    ac.onError = [&success](Client *ac) {
        DEBUG() << "connect failed, ERROR: " << errno << "\n";
        ASSERT_ERREQ(SW_ERROR_SSL_HANDSHAKE_FAILED);
        success = false;
    };

    ac.onReceive = [](Client *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    };

    ac.enable_ssl_encrypt();

    ASSERT_EQ(ac.connect("www.baidu.com", 80, 1.0), SW_OK);

    swoole_event_wait();

    ASSERT_FALSE(success);
}

TEST(client, async_tcp_http_proxy_handshake_fail) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Client ac(SW_SOCK_TCP, true);

    bool success = true;

    ac.onConnect = [&success](Client *ac) {
        ac->send(SW_STRS(GREETER));
        success = true;
    };

    ac.onClose = [](Client *ac) {};

    ac.onError = [&success](Client *ac) {
        DEBUG() << "connect failed, ERROR: " << errno << "\n";
        ASSERT_ERREQ(SW_ERROR_HTTP_PROXY_HANDSHAKE_ERROR);
        success = false;
    };

    ac.onReceive = [](Client *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    };

    ac.set_http_proxy("www.baidu.com", 80);

    ASSERT_EQ(ac.connect("www.baidu.com", 80, 1.0), SW_OK);

    swoole_event_wait();
}

TEST(client, async_tcp_socks5_proxy_handshake_fail) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Client ac(SW_SOCK_TCP, true);

    bool success = true;

    ac.onConnect = [&success](Client *ac) {
        ac->send(SW_STRS(GREETER));
        success = true;
    };

    ac.onClose = [](Client *ac) {};

    ac.onError = [&success](Client *ac) {
        DEBUG() << "connect failed, ERROR: " << errno << "\n";
        ASSERT_ERREQ(ETIMEDOUT);
        success = false;
    };

    ac.onReceive = [](Client *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    };

    ac.set_socks5_proxy("www.baidu.com", 80);

    ASSERT_EQ(ac.connect("www.baidu.com", 80, 1.0), SW_OK);

    swoole_event_wait();
}

TEST(client, sleep) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    String buf(65536);

    auto domain = TEST_HTTP_DOMAIN;

    Client client(SW_SOCK_TCP, true);
    client.onConnect = [&domain](Client *cli) {
        cli->sleep();
        swoole_timer_after(200, [cli, &domain](auto _1, auto _2) {
            auto req = swoole::test::http_get_request(domain, "/");
            cli->send(req.c_str(), req.length(), 0);
            cli->wakeup();
        });
    };

    client.onError = [](Client *cli) {};
    client.onClose = [](Client *cli) {};
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(domain, 80, -1, 0), 0);

    swoole_event_wait();

    ASSERT_TRUE(buf.contains(TEST_HTTP_EXPECT));
}

TEST(client, sleep_2) {
    auto port = __LINE__ + TEST_PORT;
    auto server_pid = swoole::test::spawn_exec([port]() {
        Server serv(TEST_HOST, port, swoole::Server::MODE_BASE, SW_SOCK_TCP);
        serv.on("Receive", [](ON_RECEIVE_PARAMS) {
            usleep(10000);
            return SW_OK;
        });
        serv.on("workerStart", [](ON_WORKER_START_PARAMS) { DEBUG() << "Worker started, PID: " << getpid() << "\n"; });
        serv.start();
    });

    ASSERT_GT(server_pid, 0);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    String buf(65536);
    String wbuf(8 * 1024 * 1024);
    wbuf.append_random_bytes(wbuf.size);

    Client client(SW_SOCK_TCP, true);
    client.onConnect = [&wbuf, server_pid](Client *cli) {
        DEBUG() << "Client connected, sending data...\n";
        cli->send(wbuf.str, wbuf.length);
        swoole_timer_after(15, [cli, server_pid](auto _1, auto _2) {
            cli->sleep();
            DEBUG() << "Client is sleeping...\n";
            swoole_timer_after(15, [cli, server_pid](auto _1, auto _2) {
                cli->wakeup();
                DEBUG() << "Client woke up, closing connection...\n";
                swoole_timer_after(15, [cli, server_pid](auto _1, auto _2) {
                    cli->close();
                    DEBUG() << "Client closed, terminating server...\n";
                    kill(server_pid, SIGTERM);
                });
            });
        });
    };

    client.onError = [](Client *cli) {
        DEBUG() << "Client error occurred, ERROR: " << swoole_get_last_error() << "\n";
    };
    client.onClose = [](Client *cli) { DEBUG() << "Client connection closed.\n"; };
    client.onReceive = [](Client *cli, const char *data, size_t length) {
        DEBUG() << "Client received data, length: " << length << "\n";
    };

    ASSERT_EQ(client.connect(TEST_HOST, port, -1, 0), 0);

    swoole_event_wait();

    swoole::test::wait_all_child_processes();
}

TEST(client, connect_refuse) {
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect(TEST_HOST, swoole::test::get_random_port(), -1, 0);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(swoole_get_last_error(), ECONNREFUSED);
}

TEST(client, bind) {
    Client cli(SW_SOCK_TCP, false);
    ASSERT_EQ(cli.bind("127.0.0.1", 9999), SW_OK);
    ASSERT_EQ(cli.bind("192.0.0.1", 9999), SW_ERR);
    ASSERT_ERREQ(EADDRNOTAVAIL);
    ASSERT_EQ(cli.bind("127.0.0.1", 80), SW_ERR);
    ASSERT_ERREQ(EACCES);
}

// DNS 报文头部结构
struct DNSHeader {
    uint16_t id;       // 标识符
    uint16_t flags;    // 各种标志
    uint16_t qdcount;  // 问题数量
    uint16_t ancount;  // 回答数量
    uint16_t nscount;  // 授权记录数量
    uint16_t arcount;  // 附加记录数量
};

// 将域名转换为 DNS 格式
std::vector<uint8_t> encodeDomainName(const std::string &domain) {
    std::vector<uint8_t> result;
    std::string label;

    for (char c : domain) {
        if (c == '.') {
            result.push_back(static_cast<uint8_t>(label.length()));
            for (char lc : label) {
                result.push_back(static_cast<uint8_t>(lc));
            }
            label.clear();
        } else {
            label += c;
        }
    }

    // 处理最后一个标签
    if (!label.empty()) {
        result.push_back(static_cast<uint8_t>(label.length()));
        for (char lc : label) {
            result.push_back(static_cast<uint8_t>(lc));
        }
    }

    // 添加结束符
    result.push_back(0);

    return result;
}

// 构建 DNS 查询报文
std::vector<uint8_t> buildDNSQuery(const std::string &domain, uint16_t recordType = 1) {
    std::vector<uint8_t> query;

    // 生成随机 ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 65535);
    uint16_t transactionId = dist(gen);

    // 构建 DNS 头部
    DNSHeader header;
    header.id = htons(transactionId);  // 网络字节序
    header.flags = htons(0x0100);      // RD=1, 其余为0
    header.qdcount = htons(1);         // 1个问题
    header.ancount = htons(0);         // 0个回答
    header.nscount = htons(0);         // 0个授权记录
    header.arcount = htons(0);         // 0个附加记录

    // 将头部添加到查询报文
    uint8_t *headerPtr = reinterpret_cast<uint8_t *>(&header);
    query.insert(query.end(), headerPtr, headerPtr + sizeof(DNSHeader));

    // 添加问题部分 - 域名
    std::vector<uint8_t> qname = encodeDomainName(domain);
    query.insert(query.end(), qname.begin(), qname.end());

    // 添加问题部分 - 查询类型和查询类
    uint16_t qtype = htons(recordType);  // 查询类型（如A记录=1）
    uint16_t qclass = htons(1);          // 查询类（IN=1）

    uint8_t *qtypePtr = reinterpret_cast<uint8_t *>(&qtype);
    uint8_t *qclassPtr = reinterpret_cast<uint8_t *>(&qclass);

    query.insert(query.end(), qtypePtr, qtypePtr + sizeof(uint16_t));
    query.insert(query.end(), qclassPtr, qclassPtr + sizeof(uint16_t));

    return query;
}

// 将二进制数据转换为十六进制字符串
std::string bytesToHexString(const std::vector<uint8_t> &data) {
    std::stringstream ss;

    for (size_t i = 0; i < data.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        if (i < data.size() - 1) {
            ss << " ";
        }
    }

    return ss.str();
}

TEST(client, sendto) {
    Client cli(SW_SOCK_TCP, false);
    ASSERT_EQ(cli.sendto("127.0.0.1", 9999, SW_STRL(TEST_STR)), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);

    auto dns_server = swoole_get_dns_server();
    Client dsock(SW_SOCK_UDP, false);
    auto dnsQuery = buildDNSQuery("www.baidu.com");
    ASSERT_EQ(dsock.sendto(dns_server.host, dns_server.port, (const char *) dnsQuery.data(), dnsQuery.size()), SW_OK);
    ASSERT_GT(dsock.recv(sw_tg_buffer()->str, sw_tg_buffer()->size), 0);

    Address ra;
    ASSERT_EQ(dsock.get_peer_name(&ra), SW_OK);
    ASSERT_STREQ(ra.get_addr(), dns_server.host.c_str());
    ASSERT_EQ(ra.get_port(), dns_server.port);

    Client cli2(SW_SOCK_UDP, false);
    ASSERT_EQ(cli2.sendto("www.baidu.com-not-exists", 9999, SW_STRL(TEST_STR)), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);

    Client cli3(SW_SOCK_UNIX_DGRAM, false);
    ASSERT_EQ(cli3.sendto("/tmp/swoole.sock", 0, SW_STRL(TEST_STR)), SW_ERR);
    ASSERT_ERREQ(ENOENT);
}

TEST(client, async_unix_connect_refuse) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    std::unordered_map<std::string, bool> flags;

    AsyncClient ac(SW_SOCK_UNIX_DGRAM);

    ac.on_connect([](AsyncClient *ac) { ac->send(SW_STRS(GREETER)); });

    ac.on_close([](AsyncClient *ac) {});

    ac.on_error([&](AsyncClient *ac) { flags["onError"] = true; });

    ac.on_receive([](AsyncClient *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    });

    bool retval = ac.connect("/tmp/swoole-not-exists.sock", 0);

    ASSERT_EQ(retval, false);
    ASSERT_TRUE(flags["onError"]);
    ASSERT_EQ(errno, ENOENT);

    swoole_event_wait();
}

TEST(client, async_connect_timeout) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    std::unordered_map<std::string, bool> flags;

    AsyncClient ac(SW_SOCK_TCP);

    ac.on_connect([](AsyncClient *ac) { ac->send(SW_STRS(GREETER)); });

    ac.on_close([](AsyncClient *ac) {});

    ac.on_error([&](AsyncClient *ac) {
        flags["onError"] = true;
        ASSERT_EQ(swoole_get_last_error(), ETIMEDOUT);
    });

    ac.on_receive([](AsyncClient *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    });

    ASSERT_TRUE(ac.connect("192.168.1.199", 19999, 0.2));
    swoole_event_wait();

    ASSERT_TRUE(flags["onError"]);
}

static void test_async_client_dgram(const char *host, int port, enum swSocketType type) {
    pid_t pid;

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    Process proc([&](Process *proc) {
        Server serv(host, port, swoole::Server::MODE_BASE, type);
        serv.on("Packet", [](ON_PACKET_PARAMS) -> int {
            swoole::DgramPacket *packet = (swoole::DgramPacket *) req->data;
            SERVER_THIS->sendto(packet->socket_addr, packet->data, packet->length, req->info.server_fd);
            return 0;
        });
        serv.on("Start", [lock](ON_START_PARAMS) { lock->unlock(); });
        serv.start();
    });

    pid = proc.start();

    lock->lock();

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    std::unordered_map<std::string, bool> flags;

    AsyncClient ac(type);

    ac.on_connect([&](AsyncClient *ac) {
        flags["onConnect"] = true;
        ac->send(SW_STRS(GREETER));
    });

    ac.on_close([&](AsyncClient *ac) { flags["onClose"] = true; });

    ac.on_error([&](AsyncClient *ac) {
        flags["onError"] = true;
        ASSERT_EQ(swoole_get_last_error(), ETIMEDOUT);
    });

    ac.on_receive([&](AsyncClient *ac, const char *data, size_t len) {
        flags["onReceive"] = true;
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    });

    ASSERT_TRUE(ac.connect(host, port, 0.2));
    swoole_event_wait();

    kill(pid, SIGTERM);
    int status;
    wait(&status);

    ASSERT_TRUE(flags["onConnect"]);
    ASSERT_TRUE(flags["onReceive"]);
    ASSERT_TRUE(flags["onClose"]);
    ASSERT_FALSE(flags["onError"]);
}

TEST(client, async_udp) {
    test_async_client_dgram(TEST_HOST, swoole::test::get_random_port(), SW_SOCK_UDP);
}

TEST(client, async_udp_dns) {
    test_async_client_dgram("localhost", swoole::test::get_random_port(), SW_SOCK_UDP);
}

TEST(client, async_udp6) {
    test_async_client_dgram("::1", swoole::test::get_random_port(), SW_SOCK_UDP6);
}

TEST(client, connect_timeout) {
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect("19.168.0.99", swoole::test::get_random_port(), 0.2, 0);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(swoole_get_last_error(), ETIMEDOUT);
}

TEST(client, shutdown_write) {
    signal(SIGPIPE, SIG_IGN);
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect("www.baidu.com", 80, -1, 0);
    ASSERT_EQ(ret, 0);
    cli.shutdown(SHUT_WR);
    ssize_t retval = cli.send(SW_STRL("hello world"), 0);
    ASSERT_EQ(retval, -1);
    ASSERT_EQ(swoole_get_last_error(), EPIPE);
}

TEST(client, shutdown_read) {
    signal(SIGPIPE, SIG_IGN);
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect("www.baidu.com", 80, -1, 0);
    ASSERT_EQ(ret, 0);

    cli.shutdown(SHUT_RD);
    ssize_t retval = cli.send(SW_STRL("hello world\r\n\r\n"), 0);
    ASSERT_GT(retval, 0);

    char buf[1024];
    retval = cli.recv(buf, sizeof(buf), 0);
    ASSERT_EQ(retval, 0);
}

TEST(client, shutdown_all) {
    signal(SIGPIPE, SIG_IGN);
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect("www.baidu.com", 80, -1, 0);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(cli.shutdown(SHUT_RDWR), SW_OK);
    ASSERT_EQ(cli.shutdown(SHUT_RDWR + 99), SW_ERR);
    ASSERT_ERREQ(EINVAL);

    ssize_t retval = cli.send(SW_STRL("hello world\r\n\r\n"), 0);
    ASSERT_EQ(retval, -1);
    ASSERT_EQ(swoole_get_last_error(), EPIPE);

    char buf[1024];
    retval = cli.recv(buf, sizeof(buf), 0);
    ASSERT_EQ(retval, 0);
}

#ifdef SW_USE_OPENSSL
static void test_ssl_http_get() {
    bool connected = false;
    bool closed = false;
    String buf(65536);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Client client(SW_SOCK_TCP, true);
    client.enable_ssl_encrypt();
    client.onConnect = [&connected](Client *cli) {
        connected = true;
        auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");
        cli->send(req.c_str(), req.length(), 0);
    };

    client.onError = [](Client *cli) {};
    client.onClose = [&closed](Client *cli) { closed = true; };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(TEST_HTTP_DOMAIN, 443, -1, 0), 0);

    swoole_event_wait();

    ASSERT_TRUE(connected);
    ASSERT_TRUE(closed);
    ASSERT_TRUE(buf.contains(TEST_HTTPS_EXPECT));
}

TEST(client, ssl_1) {
    test_ssl_http_get();
}

TEST(client, ssl_sendfile) {
    bool connected = false;
    bool closed = false;
    String buf(65536);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    auto file = swoole::make_tmpfile();
    file.write(SW_STRL(TEST_REQUEST_BAIDU));

    Client client(SW_SOCK_TCP, true);
    client.enable_ssl_encrypt();
    client.onConnect = [&connected, &file](Client *cli) {
        connected = true;
        cli->sendfile(file.get_path().c_str(), 0, file.get_size());
    };

    client.onError = [](Client *cli) {};
    client.onClose = [&closed](Client *cli) { closed = true; };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(TEST_DOMAIN_BAIDU, 443, -1, 0), 0);

    swoole_event_wait();

    ASSERT_TRUE(connected);
    ASSERT_TRUE(closed);
    ASSERT_TRUE(buf.contains("Baidu"));
}

TEST(client, sync_ssl_sendfile) {
    auto file = swoole::make_tmpfile();
    file.write(SW_STRL(TEST_REQUEST_BAIDU));

    SyncClient client(SW_SOCK_TCP);
    ASSERT_TRUE(client.connect(TEST_DOMAIN_BAIDU, 443, -1));
    ASSERT_TRUE(client.enable_ssl_encrypt());
    ASSERT_TRUE(client.sendfile(file.get_path().c_str()));

    String buf(65536);
    while (true) {
        ssize_t nr = client.recv(buf.str, buf.size - buf.length);
        if (nr <= 0) {
            break;
        }
        buf.grow(nr);
    }
    client.close();
    ASSERT_TRUE(buf.contains("baidu.com"));
    unlink(file.get_path().c_str());
}

static void proxy_async_test(Client &client, bool https) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    bool connected = false;
    bool closed = false;
    String buf(65536);

    if (https) {
        client.enable_ssl_encrypt();
    }

    client.onConnect = [&connected](Client *cli) {
        connected = true;
        cli->send(SW_STRL(TEST_REQUEST_BAIDU), 0);
    };

    client.onError = [](Client *cli) {};
    client.onClose = [&closed](Client *cli) { closed = true; };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(TEST_DOMAIN_BAIDU, https ? 443 : 80, -1, 0), 0);

    swoole_event_wait();

    ASSERT_TRUE(connected);
    ASSERT_TRUE(closed);
    ASSERT_TRUE(buf.contains("www.baidu.com"));
}

static void proxy_sync_test(Client &client, bool https) {
    String buf(65536);
    if (https) {
        client.enable_ssl_encrypt();
    }

    std::string host = TEST_DOMAIN_BAIDU;
    if (client.socks5_proxy && !client.socks5_proxy->dns_tunnel) {
        host = swoole::network::gethostbyname(AF_INET, host);
        DEBUG() << "Resolved domain " << TEST_DOMAIN_BAIDU << " to " << host << "\n";
    }

    ASSERT_EQ(client.connect(host.c_str(), https ? 443 : 80, -1, 0), 0);
    ASSERT_GT(client.send(SW_STRL(TEST_REQUEST_BAIDU), 0), 0);

    while (true) {
        char rbuf[4096];
        auto nr = client.recv(rbuf, sizeof(rbuf), 0);
        if (nr <= 0) {
            break;
        }
        buf.append(rbuf, nr);
    }

    ASSERT_TRUE(buf.contains("www.baidu.com"));
}

static void proxy_set_socks5_proxy(Client &client) {
    std::string username = std::string(TEST_SOCKS5_PROXY_USER);
    std::string password = std::string(TEST_SOCKS5_PROXY_PASSWORD);
    client.set_socks5_proxy(TEST_SOCKS5_PROXY_HOST, TEST_SOCKS5_PROXY_PORT, username, password);
}

static void proxy_set_http_proxy(Client &client) {
    std::string username, password;
    if (swoole::test::is_github_ci()) {
        username = std::string(TEST_HTTP_PROXY_USER);
        password = std::string(TEST_HTTP_PROXY_PASSWORD);
    }
    client.set_http_proxy(TEST_HTTP_PROXY_HOST, TEST_HTTP_PROXY_PORT, username, password);
}

TEST(client, https_get_async_with_http_proxy) {
    Client client(SW_SOCK_TCP, true);
    proxy_set_http_proxy(client);
    proxy_async_test(client, true);
}

TEST(client, https_get_async_with_socks5_proxy) {
    Client client(SW_SOCK_TCP, true);
    proxy_set_socks5_proxy(client);
    proxy_async_test(client, true);
}

TEST(client, https_get_sync_with_http_proxy) {
    Client client(SW_SOCK_TCP, false);
    proxy_set_http_proxy(client);
    proxy_sync_test(client, true);
}

TEST(client, https_get_sync_with_socks5_proxy) {
    Client client(SW_SOCK_TCP, false);
    proxy_set_socks5_proxy(client);
    proxy_sync_test(client, true);
}

TEST(client, http_get_sync_with_socks5_proxy_no_dns_tunnel) {
    Client client(SW_SOCK_TCP, false);
    proxy_set_socks5_proxy(client);
    client.socks5_proxy->dns_tunnel = 0;
    proxy_sync_test(client, false);
}

TEST(client, http_get_async_with_http_proxy) {
    Client client(SW_SOCK_TCP, true);
    proxy_set_http_proxy(client);
    proxy_async_test(client, false);
}

TEST(client, http_get_async_with_socks5_proxy) {
    Client client(SW_SOCK_TCP, true);
    proxy_set_socks5_proxy(client);
    proxy_async_test(client, false);
}

TEST(client, http_get_sync_with_http_proxy) {
    Client client(SW_SOCK_TCP, false);
    proxy_set_http_proxy(client);
    proxy_sync_test(client, false);
}

TEST(client, http_get_sync_with_socks5_proxy) {
    Client client(SW_SOCK_TCP, false);
    proxy_set_socks5_proxy(client);
    proxy_sync_test(client, false);
}

TEST(client, ssl) {
    Client client(SW_SOCK_TCP, false);
    client.enable_ssl_encrypt();
    client.set_tls_host_name(TEST_HTTP_DOMAIN);
    ASSERT_EQ(client.connect(TEST_HTTP_DOMAIN, 443, -1, 0), SW_OK);

    auto sock = client.socket;
    ASSERT_TRUE(sock->ssl_get_peer_certificate(sw_tg_buffer()));
    auto ls = sock->ssl_get_peer_cert_chain(10);
    ASSERT_FALSE(ls.empty());
    swoole::test::dump_cert_info(sw_tg_buffer()->str, sw_tg_buffer()->length);
    ASSERT_EQ(client.ssl_verify(false), SW_OK);

    auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");

    constexpr off_t offset1 = 87;
    iovec wr_iov[2];
    wr_iov[0].iov_base = (void *) req.c_str();
    wr_iov[0].iov_len = offset1;
    wr_iov[1].iov_base = (void *) req.c_str() + offset1;
    wr_iov[1].iov_len = req.length() - offset1;

    swoole::network::IOVector wr_vec(wr_iov, 2);
    ASSERT_EQ(sock->ssl_writev(&wr_vec), req.length());

    sw_tg_buffer()->clear();
    sw_tg_buffer()->extend(1024 * 1024);

    constexpr off_t offset2 = 1949;
    iovec rd_iov[2];
    rd_iov[0].iov_base = sw_tg_buffer()->str;
    rd_iov[0].iov_len = offset2;
    rd_iov[1].iov_base = sw_tg_buffer()->str + offset2;
    rd_iov[1].iov_len = sw_tg_buffer()->size - offset2;

    swoole::network::IOVector rd_vec(rd_iov, 2);
    auto rv = sock->ssl_readv(&rd_vec);
    ASSERT_GT(rv, 1024);
    sw_tg_buffer()->length = rv;
    sw_tg_buffer()->set_null_terminated();

    ASSERT_TRUE(sw_tg_buffer()->contains(TEST_HTTPS_EXPECT));
}
#endif

TEST(client, fail) {
    Client c((swSocketType) (SW_SOCK_RAW6 + 1), false);
    ASSERT_FALSE(c.ready());
    ASSERT_ERREQ(ESOCKTNOSUPPORT);
}

static void test_recv_timeout(Client &c) {
    std::thread t([]() {
        SW_LOOP_N(20) {
            usleep(50000);
            kill(getpid(), SIGIO);
        }
    });

    swoole_signal_set(
        SIGIO, [](int) { swoole::test::counter_incr(0); }, 0, 1);

    auto buf = sw_tg_buffer();
    while (true) {
        auto rv = c.recv(buf->str, buf->size);
        DEBUG() << "rv: " << rv << ", error=" << errno << "\n";
        if (errno == ETIMEDOUT) {
            break;
        }
    }

    t.join();
}

TEST(client, recv_timeout) {
    Client c(SW_SOCK_TCP, false);
    ASSERT_TRUE(c.ready());
    ASSERT_EQ(c.connect(TEST_HTTP_DOMAIN, 80, 1.0), SW_OK);
    test_recv_timeout(c);
}

TEST(client, ssl_recv_timeout) {
    Client c(SW_SOCK_TCP, false);
    ASSERT_TRUE(c.ready());
    c.enable_ssl_encrypt();

    ASSERT_EQ(c.connect(TEST_HTTP_DOMAIN, 443, 1.0), SW_OK);
    test_recv_timeout(c);
}
