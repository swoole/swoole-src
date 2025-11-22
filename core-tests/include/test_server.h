#pragma once

#include "test_core.h"
#include "swoole_server.h"

#define SERVER_THIS ((swoole::test::Server *) serv->private_data_2)

#define ON_START_PARAMS swoole::Server *serv
#define ON_WORKER_START_PARAMS swoole::Server *serv, swoole::Worker *worker
#define ON_PACKET_PARAMS swoole::Server *serv, swoole::RecvData *req
#define ON_RECEIVE_PARAMS swoole::Server *serv, swoole::RecvData *req

namespace swoole {
namespace test {
//--------------------------------------------------------------------------------------------------------
class Server {
  private:
    swoole::Server serv;
    std::vector<ListenPort *> ports;
    std::unordered_map<std::string, void *> private_data;
    std::string host;
    int port;
    int mode;
    int type;

    std::string tolower(const std::string &str);

  public:
    DgramPacket *packet = nullptr;

    Server(std::string _host, int _port, swoole::Server::Mode _mode, int _type);
    ~Server();

    void on(const std::string &event, const std::function<void(swServer *, Worker *)> &fn);
    void on(const std::string &event, const std::function<void(swServer *)> &fn);
    void on(const std::string &event, const std::function<void(swServer *, EventData *)> &fn);
    void on(const std::string &event, const std::function<int(swServer *, EventData *)> &fn);
    void on(const std::string &event, const std::function<int(swServer *, RecvData *)> &fn);
    void on(const std::string &event, const std::function<void(swServer *, DataHead *)> &fn);

    bool start();
    bool listen(const std::string &host, int port, enum swSocketType type);
    int send(int session_id, const void *data, uint32_t length);
    ssize_t sendto(const swoole::network::Address &address, const char *__buf, size_t __n, int server_socket = -1);
    int close(int session_id, int reset);

    inline void *get_private_data(const std::string &key) {
        auto it = private_data.find(key);
        if (it == private_data.end()) {
            return nullptr;
        } else {
            return it->second;
        }
    }

    inline void set_private_data(const std::string &key, void *data) {
        private_data[key] = data;
    }
};
//--------------------------------------------------------------------------------------------------------
}  // namespace test
}  // namespace swoole
