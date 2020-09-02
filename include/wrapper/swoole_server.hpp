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

#pragma once

#include <vector>
#include <string>
#include <map>

#include "swoole_server.h"

namespace swoole {
namespace wrapper {
//-----------------------------------namespace begin------------------------------------------------
class ClientInfo {
  public:
    char address[256];
    int port;
    int server_socket;
};

extern swString *_callback_buffer;

struct DataBuffer {
    size_t length;
    char *buffer;

    DataBuffer() {
        length = 0;
        buffer = nullptr;
    }

    DataBuffer(const char *str) {
        copy(str, strlen(str));
    }

    DataBuffer(const std::string &str) {
        copy(str.c_str(), str.length());
    }

    DataBuffer(const char *str, size_t length) {
        copy(str, length);
    }

    void copy(const char *_data, size_t _length) {
        alloc(_length);
        memcpy(buffer, _data, _length);
    }

    void *alloc(size_t _size) {
        if (_size >= _callback_buffer->size) {
            size_t new_size = _callback_buffer->size * 2;
            while (new_size < _size + 1) {
                new_size *= 2;
            }
            if (!_callback_buffer->extend(new_size)) {
                abort();
            }
        }
        length = _size;
        buffer = _callback_buffer->str;
        ((char *) buffer)[_size] = '\0';
        return buffer;
    }
};

enum {
    EVENT_onStart = 1u << 1,
    EVENT_onShutdown = 1u << 2,
    EVENT_onWorkerStart = 1u << 3,
    EVENT_onWorkerStop = 1u << 4,
    EVENT_onConnect = 1u << 5,
    EVENT_onReceive = 1u << 6,
    EVENT_onPacket = 1u << 7,
    EVENT_onClose = 1u << 8,
    EVENT_onTask = 1u << 9,
    EVENT_onFinish = 1u << 10,
    EVENT_onPipeMessage = 1u << 11,
};

class Server {
  public:
    Server(const std::string &_host, int _port, enum swServer_mode _mode = SW_MODE_PROCESS, enum swSocket_type _type = SW_SOCK_TCP);

    virtual ~Server(){};

    bool start(void);
    void setEvents(int _events);
    bool listen(const std::string &host, int port, enum swSocket_type type);
    bool send(int fd, const char *data, int length);
    bool send(int fd, const DataBuffer &data);
    bool sendfile(int fd, const std::string &file, off_t offset = 0, size_t length = 0);
    bool sendMessage(int worker_id, DataBuffer &data);
    bool sendwait(int fd, const DataBuffer &data);
    bool close(int fd, bool reset = false);
    bool sendto(const std::string &ip, int port, const DataBuffer &data, int server_socket = -1);
    int task(DataBuffer &data, int dst_worker_id = -1);
    bool finish(DataBuffer &data);
    DataBuffer taskwait(const DataBuffer &data, double timeout = SW_TASKWAIT_TIMEOUT, int dst_worker_id = -1);
    std::map<int, DataBuffer> taskWaitMulti(const std::vector<DataBuffer> &data, double timeout = SW_TASKWAIT_TIMEOUT);

    int getLastError() {
        return swoole_get_last_error();
    }

    virtual void onStart() = 0;
    virtual void onShutdown() = 0;
    virtual void onWorkerStart(int worker_id) = 0;
    virtual void onWorkerStop(int worker_id) = 0;
    virtual void onReceive(int fd, const DataBuffer &data) = 0;
    virtual void onConnect(int fd) = 0;
    virtual void onClose(int fd) = 0;
    virtual void onPacket(const DataBuffer &, ClientInfo &) = 0;
    virtual void onPipeMessage(int src_worker_id, const DataBuffer &) = 0;
    virtual void onTask(int, int, const DataBuffer &) = 0;
    virtual void onFinish(int, const DataBuffer &) = 0;

  public:
    static int _onReceive(swServer *serv, swRecvData *req);
    static int _onPacket(swServer *serv, swRecvData *req);
    static void _onConnect(swServer *serv, swDataHead *info);
    static void _onClose(swServer *serv, swDataHead *info);
    static void _onPipeMessage(swServer *serv, swEventData *req);
    static void _onStart(swServer *serv);
    static void _onShutdown(swServer *serv);
    static void _onWorkerStart(swServer *serv, int worker_id);
    static void _onWorkerStop(swServer *serv, int worker_id);
    static int _onTask(swServer *serv, swEventData *task);
    static int _onFinish(swServer *serv, swEventData *task);

  private:
    int check_task_param(int dst_worker_id);

  protected:
    swServer serv;
    std::string host;
    int port;
    enum swServer_mode mode;
    int events;
};
//-----------------------------------namespace end------------------------------------------------
}  // namespace wrapper
}  // namespace swoole
