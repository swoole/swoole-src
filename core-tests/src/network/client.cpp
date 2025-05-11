#include "test_core.h"
#include "test_server.h"
#include "test_process.h"

#define GREETER "Hello Swoole"
#define GREETER_SIZE sizeof(GREETER)

using swoole::HttpProxy;
using swoole::Mutex;
using swoole::Pipe;
using swoole::Socks5Proxy;
using swoole::String;
using swoole::network::AsyncClient;
using swoole::network::Client;
using swoole::network::SyncClient;
using swoole::test::create_http_proxy;
using swoole::test::create_socks5_proxy;
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

    sleep(1); // wait for the test server to start

    Client cli(SW_SOCK_TCP, false);
    ASSERT_NE(cli.socket, nullptr);
    ret = cli.connect(&cli, TEST_HOST, port, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);

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
    ret = cli.connect(&cli, host, port, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
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
        Server serv(TEST_HOST, port, swoole::Server::MODE_BASE, type);

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

    ac.on_close([](AsyncClient *ac) {
    });
    ac.on_error([](AsyncClient *ac) {
    });

    ac.on_receive([](AsyncClient *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    });

    bool retval = ac.connect(host, port);
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

TEST(client, sleep) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    String buf(65536);

    auto domain = TEST_HTTP_DOMAIN;

    Client client(SW_SOCK_TCP, true);
    client.onConnect = [&domain](Client *cli) {
        cli->sleep();
        swoole_timer_after(200, [cli, &domain](auto _1, auto _2) {
            auto req = swoole::test::http_get_request(domain, "/");
            cli->send(cli, req.c_str(), req.length(), 0);
            cli->wakeup();
        });
    };

    client.onError = [](Client *cli) {
    };
    client.onClose = [](Client *cli) {
    };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(&client, domain, 80, -1, 0), 0);

    swoole_event_wait();

    ASSERT_TRUE(buf.contains(TEST_HTTP_EXPECT));
}

TEST(client, connect_refuse) {
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect(&cli, TEST_HOST, swoole::test::get_random_port(), -1, 0);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(swoole_get_last_error(), ECONNREFUSED);
}

TEST(client, async_unix_connect_refuse) {
    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    std::unordered_map<std::string, bool> flags;

    AsyncClient ac(SW_SOCK_UNIX_DGRAM);

    ac.on_connect([](AsyncClient *ac) { ac->send(SW_STRS(GREETER)); });

    ac.on_close([](AsyncClient *ac) {
    });

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

    ac.on_close([](AsyncClient *ac) {
    });

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
    ret = cli.connect(&cli, "19.168.0.99", swoole::test::get_random_port(), 0.2, 0);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(swoole_get_last_error(), ETIMEDOUT);
}

TEST(client, shutdown_write) {
    signal(SIGPIPE, SIG_IGN);
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect(&cli, "www.baidu.com", 80, -1, 0);
    ASSERT_EQ(ret, 0);
    cli.shutdown(SHUT_WR);
    ssize_t retval = cli.send(&cli, SW_STRL("hello world"), 0);
    ASSERT_EQ(retval, -1);
    ASSERT_EQ(swoole_get_last_error(), EPIPE);
}

TEST(client, shutdown_read) {
    signal(SIGPIPE, SIG_IGN);
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect(&cli, "www.baidu.com", 80, -1, 0);
    ASSERT_EQ(ret, 0);

    cli.shutdown(SHUT_RD);
    ssize_t retval = cli.send(&cli, SW_STRL("hello world\r\n\r\n"), 0);
    ASSERT_GT(retval, 0);

    char buf[1024];
    retval = cli.recv(&cli, buf, sizeof(buf), 0);
    ASSERT_EQ(retval, 0);
}

TEST(client, shutdown_all) {
    signal(SIGPIPE, SIG_IGN);
    int ret;
    Client cli(SW_SOCK_TCP, false);
    ret = cli.connect(&cli, "www.baidu.com", 80, -1, 0);
    ASSERT_EQ(ret, 0);

    cli.shutdown(SHUT_RDWR);

    ssize_t retval = cli.send(&cli, SW_STRL("hello world\r\n\r\n"), 0);
    ASSERT_EQ(retval, -1);
    ASSERT_EQ(swoole_get_last_error(), EPIPE);

    char buf[1024];
    retval = cli.recv(&cli, buf, sizeof(buf), 0);
    ASSERT_EQ(retval, 0);
}

#ifdef SW_USE_OPENSSL

TEST(client, ssl_1) {
    bool connected = false;
    bool closed = false;
    String buf(65536);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    Client client(SW_SOCK_TCP, true);
    client.enable_ssl_encrypt();
    client.onConnect = [&connected](Client *cli) {
        connected = true;
        cli->send(cli, SW_STRL(TEST_REQUEST_BAIDU), 0);
    };

    client.onError = [](Client *cli) {
    };
    client.onClose = [&closed](Client *cli) { closed = true; };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(&client, TEST_DOMAIN_BAIDU, 443, -1, 0), 0);

    swoole_event_wait();

    ASSERT_TRUE(connected);
    ASSERT_TRUE(closed);
    ASSERT_TRUE(buf.contains("Baidu"));
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
        cli->sendfile(cli, file.get_path().c_str(), 0, file.get_size());
    };

    client.onError = [](Client *cli) {
    };
    client.onClose = [&closed](Client *cli) { closed = true; };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(&client, TEST_DOMAIN_BAIDU, 443, -1, 0), 0);

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
        cli->send(cli, SW_STRL(TEST_REQUEST_BAIDU), 0);
    };

    client.onError = [](Client *cli) {
    };
    client.onClose = [&closed](Client *cli) { closed = true; };
    client.onReceive = [&buf](Client *cli, const char *data, size_t length) { buf.append(data, length); };

    ASSERT_EQ(client.connect(&client, TEST_DOMAIN_BAIDU, https ? 443 : 80, -1, 0), 0);

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

    ASSERT_EQ(client.connect(&client, TEST_DOMAIN_BAIDU, https ? 443 : 80, -1, 0), 0);
    ASSERT_GT(client.send(&client, SW_STRL(TEST_REQUEST_BAIDU), 0), 0);

    while (true) {
        char rbuf[4096];
        auto nr = client.recv(&client, rbuf, sizeof(rbuf), 0);
        if (nr <= 0) {
            break;
        }
        buf.append(rbuf, nr);
    }

    ASSERT_TRUE(buf.contains("www.baidu.com"));
}

static void proxy_set_socks5_proxy(Client &client) {
    client.socks5_proxy = create_socks5_proxy();
}

static void proxy_set_http_proxy(Client &client) {
    client.http_proxy = create_http_proxy();
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



void printAllSubjectEntries(X509_NAME* name) {
    if (!name) return;

    int entry_count = X509_NAME_entry_count(name);

    for (int i = 0; i < entry_count; ++i) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);

        // 获取字段的短名称（如 CN、O、ST 等）
        char obj_txt[80] = {0};
        OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);

        // 获取字段的值
        unsigned char* utf8 = nullptr;
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (length >= 0 && utf8) {
            std::cout << obj_txt << ": " << std::string((char*)utf8, length) << std::endl;
            OPENSSL_free(utf8);
        }
    }
}

void printX509Info(X509 *cert) {
    X509_NAME *subject_name = X509_get_subject_name(cert);
    printAllSubjectEntries(subject_name);

    char *subject = X509_NAME_oneline(subject_name, 0, 0);
    if (subject) {
        printf("Peer certificate subject: %s\n", subject);
        OPENSSL_free(subject);
    }

    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    printAllSubjectEntries(issuer_name);

    // 获取证书有效期
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, not_before);
    char buf[256] = {0};
    int len = BIO_read(bio, buf, sizeof(buf) - 1);
    buf[len] = 0;
    std::cout << "Validity Not Before: " << buf << std::endl;

    ASN1_TIME_print(bio, not_after);
    len = BIO_read(bio, buf, sizeof(buf) - 1);
    buf[len] = 0;
    std::cout << "Validity Not After: " << buf << std::endl;

    BIO_free(bio);

    // 获取公钥
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (pubkey) {
        std::cout << "Public key type: " << EVP_PKEY_id(pubkey) << std::endl;
        EVP_PKEY_free(pubkey);
    }
}

int dump_cert_info(const char *data, size_t len) {
    BIO *bio = BIO_new_mem_buf(data, (int) len);
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        return 1;
    }

    // 从 BIO 中读取证书
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) {
        std::cerr << "Failed to parse X509 certificate" << std::endl;
        BIO_free(bio);
        return 1;
    }

    // 打印证书信息
    printX509Info(cert);

    // 释放资源
    X509_free(cert);
    BIO_free(bio);
    EVP_cleanup();

    return 0;
}

TEST(client, ssl) {
    Client client(SW_SOCK_TCP, false);
    client.enable_ssl_encrypt();
    client.set_tls_host_name(TEST_HTTP_DOMAIN);
    ASSERT_EQ(client.connect(&client, TEST_HTTP_DOMAIN, 443, -1, 0), SW_OK);

    auto sock = client.socket;
    ASSERT_TRUE(sock->ssl_get_peer_certificate(sw_tg_buffer()));
    auto ls = sock->ssl_get_peer_cert_chain(10);
    ASSERT_FALSE(ls.empty());
    dump_cert_info(sw_tg_buffer()->str, sw_tg_buffer()->length);
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

    ASSERT_TRUE(sw_tg_buffer()->contains("中华人民共和国"));
}
#endif
