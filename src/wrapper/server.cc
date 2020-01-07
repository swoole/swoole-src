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

#include "wrapper/server.hpp"
#include <sys/stat.h>

namespace swoole
{
swString *_callback_buffer;
Server::Server(string _host, int _port, int _mode,  enum swSocket_type _type)
{
    host = _host;
    port = _port;
    mode = _mode;

    swServer_init(&serv);

    if (_mode == SW_MODE_BASE)
    {
        serv.reactor_num = 1;
        serv.worker_num = 1;
    }

    serv.factory_mode = (uint8_t) mode;
    serv.dispatch_mode = 2;

    //create Server
    int ret = swServer_create(&serv);
    if (ret < 0)
    {
        swTrace("create server fail[error=%d].\n", ret);
        exit(0);
    }
    this->listen(host, port, _type);
}

void Server::setEvents(int _events)
{
    events = _events;
}

bool Server::listen(string host, int port, enum swSocket_type type)
{
    auto ls = swServer_add_port(&serv, type, (char *) host.c_str(), port);
    if (ls == NULL)
    {
        return false;
    }
    else
    {
        ports.push_back(ls);
        return true;
    }
}

bool Server::send(int fd, const DataBuffer &data)
{
    if (serv.gs->start == 0)
    {
        return false;
    }
    if (data.length <= 0)
    {
        return false;
    }
    return serv.send(&serv, fd, (char *) data.buffer, data.length) == 0;
}

bool Server::send(int fd, const char *data, int length)
{
    if (serv.gs->start == 0)
    {
        return false;
    }
    if (length <= 0)
    {
        return false;
    }
    return serv.send(&serv, fd, (char *) data, length) == SW_OK;
}

bool Server::close(int fd, bool reset)
{
    if (serv.gs->start == 0)
    {
        return false;
    }
    if (swIsMaster())
    {
        return false;
    }

    swConnection *conn = swServer_connection_verify_no_ssl(&serv, fd);
    if (!conn)
    {
        return false;
    }

    //Reset send buffer, Immediately close the connection.
    if (reset)
    {
        conn->close_reset = 1;
    }

    int ret;
    if (!swIsWorker())
    {
        swWorker *worker = swServer_get_worker(&serv, conn->fd % serv.worker_num);
        swDataHead ev;
        ev.type = SW_SERVER_EVENT_CLOSE;
        ev.fd = fd;
        ev.reactor_id = conn->reactor_id;
        ret = swWorker_send2worker(worker, &ev, sizeof(ev), SW_PIPE_MASTER);
    }
    else
    {
        ret = serv.factory.end(&serv.factory, fd);
    }
    return ret == SW_OK;
}

static int task_id = 0;

static int task_pack(swEventData *task, const DataBuffer &data)
{
    task->info.type = SW_SERVER_EVENT_TASK;
    //field fd save task_id
    task->info.fd = task_id++;
    //field reactor_id save the worker_id
    task->info.reactor_id = SwooleWG.id;
    swTask_type(task) = 0;

    if (data.length >= SW_IPC_MAX_SIZE - sizeof(task->info))
    {
        if (swTaskWorker_large_pack(task, (char *) data.buffer, (int) data.length) < 0)
        {
            swWarn("large task pack failed()");
            return SW_ERR;
        }
    }
    else
    {
        memcpy(task->data, (char *) data.buffer, data.length);
        task->info.len = (uint16_t) data.length;
    }
    return task->info.fd;
}

static DataBuffer task_unpack(swEventData *task_result)
{
    DataBuffer retval;
    swString *result = swTaskWorker_large_unpack(task_result);
    if (result)
    {
        retval.copy(task_result->data, (size_t) task_result->info.len);
    }
    return retval;
}

static DataBuffer get_recv_data(swServer *serv, swEventData *req, char *header, uint32_t header_length)
{
    char *data_ptr = NULL;
    DataBuffer retval;
    size_t data_len = serv->get_packet(serv, req, &data_ptr);

    if (header_length >= (uint32_t) data_len)
    {
        return retval;
    }
    else
    {
        retval.copy(data_ptr + header_length, data_len - header_length);
    }

    if (header_length > 0)
    {
        memcpy(header, data_ptr, header_length);
    }

    return retval;
}

int Server::check_task_param(int dst_worker_id)
{
    if (serv.task_worker_num < 1)
    {
        swWarn("Task method cannot use, Please set task_worker_num");
        return SW_ERR;
    }
    if (dst_worker_id > 0 && (uint32_t) dst_worker_id >= serv.task_worker_num)
    {
        swWarn("worker_id must be less than serv->task_worker_num");
        return SW_ERR;
    }
    if (!swIsWorker())
    {
        swWarn("The method can only be used in the worker process");
        return SW_ERR;
    }
    return SW_OK;
}

int Server::task(DataBuffer &data, int dst_worker_id)
{
    if (serv.gs->start == 0)
    {
        swWarn("Server is not running");
        return false;
    }

    swEventData buf;
    bzero(&buf.info, sizeof(buf.info));
    if (check_task_param(dst_worker_id) < 0)
    {
        return false;
    }

    if (task_pack(&buf, data) < 0)
    {
        return false;
    }

    swTask_type(&buf) |= SW_TASK_NONBLOCK;
    if (swProcessPool_dispatch(&serv.gs->task_workers, &buf, &dst_worker_id) >= 0)
    {
        sw_atomic_fetch_add(&serv.stats->tasking_num, 1);
        return buf.info.fd;
    }
    else
    {
        return -1;
    }
}

bool Server::finish(DataBuffer &data)
{
    if (serv.gs->start == 0)
    {
        swWarn("Server is not running");
        return false;
    }
    return swTaskWorker_finish(&serv, (char *) data.buffer, (int) data.length, 0, nullptr) == 0;
}

bool Server::sendto(const string &ip, int port, const DataBuffer &data, int server_socket)
{
    if (serv.gs->start == 0)
    {
        return false;
    }
    if (data.length <= 0)
    {
        return false;
    }
    bool ipv6 = false;
    if (strchr(ip.c_str(), ':'))
    {
        ipv6 = true;
    }

    if (ipv6 && serv.udp_socket_ipv6 <= 0)
    {
        return false;
    }
    else if (serv.udp_socket_ipv4 <= 0)
    {
        swWarn("You must add an UDP listener to server before using sendto");
        return false;
    }

    if (server_socket < 0)
    {
        server_socket = ipv6 ? serv.udp_socket_ipv6 : serv.udp_socket_ipv4;
    }

    int ret;
    if (ipv6)
    {
        ret = swSocket_udp_sendto6(server_socket, (char *) ip.c_str(), port, (char *) data.buffer, data.length);
    }
    else
    {
        ret = swSocket_udp_sendto(server_socket, (char *) ip.c_str(), port, (char *) data.buffer, data.length);
    }
    return ret > 0;
}

bool Server::sendfile(int fd, string &file, off_t offset, size_t length)
{
    if (serv.gs->start == 0)
    {
        swWarn("Server is not running");
        return false;
    }

    struct stat file_stat;
    if (stat(file.c_str(), &file_stat) < 0)
    {
        swWarn("stat(%s) failed", file.c_str());
        return false;
    }
    if (file_stat.st_size <= offset)
    {
        swWarn("file[offset=%jd] is empty", (intmax_t) offset);
        return false;
    }
    return serv.sendfile(&serv, fd, (char *) file.c_str(), file.length(), offset, length) == SW_OK;
}

bool Server::sendMessage(int worker_id, DataBuffer &data)
{
    swEventData buf;

    if (serv.gs->start == 0)
    {
        swWarn("Server is not running");
        return false;
    }

    if (worker_id == (int) SwooleWG.id)
    {
        swWarn("cannot send message to self");
        return false;
    }

    if (worker_id > 0 && (uint32_t) worker_id >= serv.worker_num + serv.task_worker_num)
    {
        swWarn("worker_id[%d] is invalid", worker_id);
        return false;
    }

    if (serv.onPipeMessage == NULL)
    {
        swWarn("onPipeMessage is null, cannot use sendMessage");
        return false;
    }

    if (task_pack(&buf, data) < 0)
    {
        return false;
    }

    buf.info.type = SW_SERVER_EVENT_PIPE_MESSAGE;
    buf.info.reactor_id = SwooleWG.id;

    swWorker *to_worker = swServer_get_worker(&serv, (uint16_t) worker_id);
    return swWorker_send2worker(to_worker, &buf, sizeof(buf.info) + buf.info.len, SW_PIPE_MASTER | SW_PIPE_NONBLOCK)
            == SW_OK;
}

bool Server::sendwait(int fd, const DataBuffer &data)
{
    if (serv.gs->start == 0)
    {
        swWarn("Server is not running");
        return false;
    }
    if (data.length <= 0)
    {
        return false;
    }
    if (serv.factory_mode != SW_MODE_BASE || swIsTaskWorker())
    {
        swWarn("cannot sendwait");
        return false;
    }
    return serv.sendwait(&serv, fd, data.buffer, data.length) == 0;
}

bool Server::start(void)
{
    serv.ptr2 = this;
    if (this->events & EVENT_onStart)
    {
        serv.onStart = Server::_onStart;
    }
    if (this->events & EVENT_onShutdown)
    {
        serv.onShutdown = Server::_onShutdown;
    }
    if (this->events & EVENT_onConnect)
    {
        serv.onConnect = Server::_onConnect;
    }
    if (this->events & EVENT_onReceive)
    {
        serv.onReceive = Server::_onReceive;
    }
    if (this->events & EVENT_onPacket)
    {
        serv.onPacket = Server::_onPacket;
    }
    if (this->events & EVENT_onClose)
    {
        serv.onClose = Server::_onClose;
    }
    if (this->events & EVENT_onWorkerStart)
    {
        serv.onWorkerStart = Server::_onWorkerStart;
    }
    if (this->events & EVENT_onWorkerStop)
    {
        serv.onWorkerStop = Server::_onWorkerStop;
    }
    if (this->events & EVENT_onTask)
    {
        serv.onTask = Server::_onTask;
    }
    if (this->events & EVENT_onFinish)
    {
        serv.onFinish = Server::_onFinish;
    }
    if (this->events & EVENT_onPipeMessage)
    {
        serv.onPipeMessage = Server::_onPipeMessage;
    }
    _callback_buffer = swString_new(8192);
    int ret = swServer_start(&serv);
    if (ret < 0)
    {
        swTrace("start server fail[error=%d].\n", ret);
        return false;
    }
    return true;
}

int Server::_onReceive(swServer *serv, swEventData *req)
{
    DataBuffer data = get_recv_data(serv, req, NULL, 0);
    Server *_this = (Server *) serv->ptr2;
    _this->onReceive(req->info.fd, data);
    return SW_OK;
}

void Server::_onWorkerStart(swServer *serv, int worker_id)
{
    Server *_this = (Server *) serv->ptr2;
    _this->onWorkerStart(worker_id);
}

void Server::_onWorkerStop(swServer *serv, int worker_id)
{
    Server *_this = (Server *) serv->ptr2;
    _this->onWorkerStop(worker_id);
}

int Server::_onPacket(swServer *serv, swEventData *req)
{
    swDgramPacket *packet;

    char *buffer;
    serv->get_packet(serv, req, &buffer);
    packet = (swDgramPacket *) buffer;

    char *data = NULL;
    int length = 0;
    ClientInfo clientInfo;
    clientInfo.server_socket = req->info.server_fd;
    data = packet->data;
    length = packet->length;

    if (packet->socket_type == SW_SOCK_UDP)
    {
        inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v4.sin_addr, clientInfo.address, sizeof(clientInfo.address));
        clientInfo.port = ntohs(packet->socket_addr.addr.inet_v4.sin_port);
    }
    else if (packet->socket_type == SW_SOCK_UDP6)
    {
        inet_ntop(AF_INET6, &packet->socket_addr.addr.inet_v6.sin6_addr, clientInfo.address, sizeof(clientInfo.address));
        clientInfo.port = ntohs(packet->socket_addr.addr.inet_v6.sin6_port);
    }
    else if (packet->socket_type == SW_SOCK_UNIX_DGRAM)
    {
        strcpy(clientInfo.address, packet->socket_addr.addr.un.sun_path);
    }
    else
    {
        abort();
        return SW_ERR;
    }

    DataBuffer _data;
    _data.copy(data, length);

    Server *_this = (Server *) serv->ptr2;
    _this->onPacket(_data, clientInfo);

    return SW_OK;
}

void Server::_onStart(swServer *serv)
{
    Server *_this = (Server *) serv->ptr2;
    _this->onStart();
}

void Server::_onShutdown(swServer *serv)
{
    Server *_this = (Server *) serv->ptr2;
    _this->onShutdown();
}

void Server::_onConnect(swServer *serv, swDataHead *info)
{
    Server *_this = (Server *) serv->ptr2;
    _this->onConnect(info->fd);
}

void Server::_onClose(swServer *serv, swDataHead *info)
{
    Server *_this = (Server *) serv->ptr2;
    _this->onClose(info->fd);
}

void Server::_onPipeMessage(swServer *serv, swEventData *req)
{
    DataBuffer data = task_unpack(req);
    Server *_this = (Server *) serv->ptr2;
    _this->onPipeMessage(req->info.reactor_id, data);
}

int Server::_onTask(swServer *serv, swEventData *task)
{
    Server *_this = (Server *) serv->ptr2;
    DataBuffer data = task_unpack(task);
    _this->onTask(task->info.fd, task->info.server_fd, data);
    return SW_OK;
}

int Server::_onFinish(swServer *serv, swEventData *task)
{
    Server *_this = (Server *) serv->ptr2;
    DataBuffer data = task_unpack(task);
    _this->onFinish(task->info.fd, data);
    return SW_OK;
}

DataBuffer Server::taskwait(const DataBuffer &data, double timeout, int dst_worker_id)
{
    swEventData buf;
    DataBuffer retval;

    if (serv.gs->start == 0)
    {
        swWarn("server is not running");
        return retval;
    }

    if (check_task_param(dst_worker_id) < 0)
    {
        return retval;
    }

    task_pack(&buf, data);

    uint64_t notify;
    swEventData *task_result = &(serv.task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv.task_notify[SwooleWG.id];
    swSocket *task_notify_socket = task_notify_pipe->getSocket(task_notify_pipe, 0);

    //clear history task
    while (read(task_notify_socket->fd, &notify, sizeof(notify)) > 0) {}

    if (swProcessPool_dispatch_blocking(&serv.gs->task_workers, &buf, &dst_worker_id) >= 0)
    {
        sw_atomic_fetch_add(&serv.stats->tasking_num, 1);
        task_notify_pipe->timeout = timeout;
        int ret = task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify));
        if (ret > 0)
        {
            return task_unpack(task_result);
        }
        else
        {
            swSysWarn("taskwait failed");
        }
    }
    return retval;
}

map<int, DataBuffer> Server::taskWaitMulti(const vector<DataBuffer> &tasks, double timeout)
{
    swEventData buf;
    map<int, DataBuffer> retval;

    if (serv.gs->start == 0)
    {
        swWarn("server is not running");
        return retval;
    }

    int dst_worker_id;
    int task_id;
    int i = 0;
    int n_task = tasks.size();

    int list_of_id[1024];

    uint64_t notify;
    swEventData *task_result = &(serv.task_result[SwooleWG.id]);
    bzero(task_result, sizeof(swEventData));
    swPipe *task_notify_pipe = &serv.task_notify[SwooleWG.id];
    swWorker *worker = swServer_get_worker(&serv, SwooleWG.id);

    char _tmpfile[sizeof(SW_TASK_TMP_FILE)] = SW_TASK_TMP_FILE;
    int _tmpfile_fd = swoole_tmpfile(_tmpfile);
    if (_tmpfile_fd < 0)
    {
        swSysWarn("mktemp(%s) failed", SW_TASK_TMP_FILE);
        return retval;
    }

    close(_tmpfile_fd);
    int *finish_count = (int *) task_result->data;

    worker->lock.lock(&worker->lock);
    *finish_count = 0;
    memcpy(task_result->data + 4, _tmpfile, sizeof(_tmpfile));
    worker->lock.unlock(&worker->lock);

    //clear history task
    swSocket *task_notify_socket = task_notify_pipe->getSocket(task_notify_pipe, 0);
    while (read(task_notify_socket->fd, &notify, sizeof(notify)) > 0) {}

    for (auto task = tasks.begin(); task != tasks.end();)
    {
        task_id = task_pack(&buf, *task);
        if (task_id < 0)
        {
            swWarn("task pack failed");
            goto _fail;
        }
        swTask_type(&buf) |= SW_TASK_WAITALL;
        dst_worker_id = -1;
        if (swProcessPool_dispatch_blocking(&serv.gs->task_workers, &buf, &dst_worker_id) >= 0)
        {
            sw_atomic_fetch_add(&serv.stats->tasking_num, 1);
            list_of_id[i] = task_id;
        }
        else
        {
            swSysWarn("taskwait failed");
            _fail:
            retval[i] = DataBuffer();
            n_task--;
        }
        i++;
    }

    while (n_task > 0)
    {
        task_notify_pipe->timeout = timeout;
        int ret = task_notify_pipe->read(task_notify_pipe, &notify, sizeof(notify));
        if (ret > 0)
        {
            if (*finish_count == n_task)
            {
                break;
            }
        }
        else
        {
            swSysWarn("taskwait failed");
            unlink(_tmpfile);
            return retval;
        }
    }

    swString *content = swoole_file_get_contents(_tmpfile);
    if (content == NULL)
    {
        return retval;
    }

    swEventData *result;
    DataBuffer zdata;
    int j;

    for (i = 0; i < n_task; i++)
    {
        result = (swEventData *) (content->str + content->offset);
        task_id = result->info.fd;
        zdata = task_unpack(result);
        for (j = 0; j < n_task; j++)
        {
            if (list_of_id[j] == task_id)
            {
                break;
            }
        }
        retval[j] = zdata;
        content->offset += sizeof(swDataHead) + result->info.len;
    }
    unlink(_tmpfile);
    swString_free(content);
    return retval;
}

}
