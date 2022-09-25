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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
 */

#include "php_swoole_server.h"
#include "swoole_process_pool.h"
#include "php_swoole_http.h"
#include "php_swoole_x_arginfo.h"

#include <sstream>
#include <thread>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace swoole {

#ifdef TCP_INFO
static json get_socket_info(int fd);
#endif

static std::string handle_get_all_unix_sockets(Server *_server, const std::string &msg) {
    auto _result = json::parse(msg);
    if (!_result.is_object() || _result.find("type") == _result.end()) {
        json return_value{
            {"data", "require parameter type"},
            {"code", 4003},
        };
        return return_value.dump();
    }

    std::string _type = _result["type"];
    Worker *workers;
    uint32_t worker_num;

    if (_type == "event") {
        workers = _server->gs->event_workers.workers;
        worker_num = _server->worker_num;
    } else {
        workers = _server->gs->task_workers.workers;
        worker_num = _server->task_worker_num;
    }

    json sockets = json::array();

    SW_LOOP_N(worker_num) {
        auto master_socket = workers[i].pipe_object->get_socket(true);
        json master_socket_info = json::object({
            {"fd", master_socket->fd},
            {"events", master_socket->events},
            {"total_recv_bytes", master_socket->total_recv_bytes},
            {"total_send_bytes", master_socket->total_send_bytes},
            {"out_buffer_size", master_socket->out_buffer ? master_socket->out_buffer->length() : 0},
        });
        sockets.push_back(master_socket_info);

        auto worker_socket = workers[i].pipe_object->get_socket(false);
        json worker_socket_info = json::object({
            {"fd", worker_socket->fd},
            {"events", worker_socket->events},
            {"total_recv_bytes", worker_socket->total_recv_bytes},
            {"total_send_bytes", worker_socket->total_send_bytes},
            {"out_buffer_size", worker_socket->out_buffer ? worker_socket->out_buffer->length() : 0},
        });
        sockets.push_back(worker_socket_info);
    }

    json return_value{
        {"data", sockets},
        {"code", 0},
    };
    return return_value.dump();
}

static std::string handle_get_all_sockets(Server *, const std::string &msg) {
    if (sw_reactor() == nullptr) {
        json return_value{
            {"data", "No event loop created"},
            {"code", 4004},
        };
        return return_value.dump();
    }

    json sockets = json::array();
    sw_reactor()->foreach_socket([&sockets](int fd, network::Socket *socket) {
        network::Address addr{};
        if (socket->socket_type > SW_SOCK_UNIX_DGRAM || socket->socket_type < SW_SOCK_TCP) {
#ifdef SO_DOMAIN
            struct stat fdstat;
            if (fstat(fd, &fdstat) == -1) {
                return;
            }
            mode_t type = fdstat.st_mode & S_IFMT;
            if (type == S_IFSOCK) {
                int domain;
                if (socket->get_option(SOL_SOCKET, SO_DOMAIN, &domain) < 0) {
                    return;
                }
                int type;
                if (socket->get_option(SOL_SOCKET, SO_TYPE, &type) < 0) {
                    return;
                }
                addr.type = network::Socket::convert_to_type(domain, type);
                socket->get_name(&addr);
            }
#else
            return;
#endif
        } else {
            addr = socket->info;
        }
        json info = json::object({
            {"fd", socket->fd},
            {"address", addr.get_ip()},
            {"port", addr.get_port()},
            {"events", socket->events},
            {"socket_type", socket->socket_type},
            {"fd_type", socket->fd_type},
            {"total_recv_bytes", socket->total_recv_bytes},
            {"total_send_bytes", socket->total_send_bytes},
            {"out_buffer_size", socket->out_buffer ? socket->out_buffer->length() : 0},
        });
        sockets.push_back(info);
    });

    json return_value{
        {"data", sockets},
        {"code", 0},
    };
    return return_value.dump();
}

static std::string handle_get_all_commands(Server *serv, const std::string &msg) {
    json command_list = json::array();
    for (auto kv : serv->commands) {
        json info = json::object({
            {"id", kv.second.id},
            {"name", kv.second.name},
            {"accepted_process_types", kv.second.accepted_process_types},
        });
        command_list.push_back(info);
    };
    json return_value{
        {"data", command_list},
        {"code", 0},
    };
    return return_value.dump();
}

#ifdef TCP_INFO
static json get_socket_info(int fd) {
    struct tcp_info info;
    socklen_t len = sizeof(info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) < 0) {
        json return_value{
            {"data", "failed to getsockopt(TCP_INFO) for socket"},
            {"code", 5001},
        };
        return return_value.dump();
    }
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    json jinfo{
        {"state", info.tcpi_state},
        {"ca_state", info.__tcpi_ca_state},
        {"retransmits", info.__tcpi_retransmits},
        {"probes", info.__tcpi_probes},
        {"backoff", info.__tcpi_backoff},
        {"options", info.tcpi_options},
        {"snd_wscale", uint8_t(info.tcpi_snd_wscale)},
        {"rcv_wscale", uint8_t(info.tcpi_rcv_wscale)},
        {"rto", info.tcpi_rto},
        {"ato", info.__tcpi_ato},
        {"snd_mss", info.tcpi_snd_mss},
        {"rcv_mss", info.tcpi_rcv_mss},
        {"unacked", info.__tcpi_unacked},
        {"sacked", info.__tcpi_sacked},
        {"lost", info.__tcpi_lost},
        {"retrans", info.__tcpi_retrans},
        {"fackets", info.__tcpi_fackets},
        {"last_data_sent", info.__tcpi_last_data_sent},
        {"last_ack_sent", info.__tcpi_last_ack_sent},
        {"last_data_recv", info.tcpi_last_data_recv},
        {"last_ack_recv", info.__tcpi_last_ack_recv},
        {"pmtu", info.__tcpi_pmtu},
        {"rcv_ssthresh", info.__tcpi_rcv_ssthresh},
        {"rtt", info.tcpi_rtt},
        {"rttvar", info.tcpi_rttvar},
        {"snd_ssthresh", info.tcpi_snd_ssthresh},
        {"snd_cwnd", info.tcpi_snd_cwnd},
        {"advmss", info.__tcpi_advmss},
        {"reordering", info.__tcpi_reordering},
        {"rcv_rtt", info.__tcpi_rcv_rtt},
        {"rcv_space", info.tcpi_rcv_space},
        {"snd_wnd", info.tcpi_snd_wnd},
        {"snd_nxt", info.tcpi_snd_nxt},
        {"rcv_nxt", info.tcpi_rcv_nxt},
        {"toe_tid", info.tcpi_toe_tid},
        {"total_retrans", info.tcpi_snd_rexmitpack},
        {"rcv_ooopack", info.tcpi_rcv_ooopack},
        {"snd_zerowin", info.tcpi_snd_zerowin},
    };
#else
    json jinfo{
        {"state", info.tcpi_state},
        {"ca_state", info.tcpi_ca_state},
        {"retransmits", info.tcpi_retransmits},
        {"probes", info.tcpi_probes},
        {"backoff", info.tcpi_backoff},
        {"options", info.tcpi_options},
        {"snd_wscale", uint8_t(info.tcpi_snd_wscale)},
        {"rcv_wscale", uint8_t(info.tcpi_rcv_wscale)},
        {"rto", info.tcpi_rto},
        {"ato", info.tcpi_ato},
        {"snd_mss", info.tcpi_snd_mss},
        {"rcv_mss", info.tcpi_rcv_mss},
        {"unacked", info.tcpi_unacked},
        {"sacked", info.tcpi_sacked},
        {"lost", info.tcpi_lost},
        {"retrans", info.tcpi_retrans},
        {"fackets", info.tcpi_fackets},
        {"last_data_sent", info.tcpi_last_data_sent},
        {"last_ack_sent", info.tcpi_last_ack_sent},
        {"last_data_recv", info.tcpi_last_data_recv},
        {"last_ack_recv", info.tcpi_last_ack_recv},
        {"pmtu", info.tcpi_pmtu},
        {"rcv_ssthresh", info.tcpi_rcv_ssthresh},
        {"rtt", info.tcpi_rtt},
        {"rttvar", info.tcpi_rttvar},
        {"snd_ssthresh", info.tcpi_snd_ssthresh},
        {"snd_cwnd", info.tcpi_snd_cwnd},
        {"advmss", info.tcpi_advmss},
        {"reordering", info.tcpi_reordering},
        {"rcv_rtt", info.tcpi_rcv_rtt},
        {"rcv_space", info.tcpi_rcv_space},
        {"total_retrans", info.tcpi_total_retrans},
    };
#endif
    return jinfo;
}
#endif

static json get_connection_info(Server *serv, Connection *conn) {
    auto server_socket = serv->get_port_by_server_fd(conn->server_fd)->socket;
    json info = json::object({
        {"session_id", conn->session_id},
        {"reactor_id", conn->reactor_id},
        {"fd", conn->fd},
        {"server_port",
         std::string(server_socket->info.get_ip()) + ":" + std::to_string(server_socket->info.get_port())},
        {"address", conn->info.get_ip()},
        {"port", conn->info.get_port()},
        {"overflow", conn->overflow},
        {"connect_time", conn->connect_time},
        {"last_recv_time", conn->last_recv_time},
        {"last_send_time", conn->last_send_time},
        {"last_dispatch_time", conn->last_dispatch_time},
        {"recv_queued_bytes", conn->recv_queued_bytes},
        {"send_queued_bytes", conn->send_queued_bytes},
        {"total_recv_bytes", conn->socket->total_recv_bytes},
        {"total_send_bytes", conn->socket->total_send_bytes},
        {"uid", conn->uid},
    });
    return info;
}

static std::string handle_get_socket_info(Server *serv, const std::string &msg) {
    auto _result = json::parse(msg);
    if (!_result.is_object() || _result.find("fd") == _result.end()) {
        json return_value{
            {"data", "require parameter fd"},
            {"code", 4003},
        };
        return return_value.dump();
    }

#ifndef TCP_INFO
    json return_value{
        {"data", "platform unsupported"},
        {"code", 5001},
    };
#else
    std::string _fd = _result["fd"];
    int fd = std::atoi(_fd.c_str());
    json return_value{
        {"data", get_socket_info(fd)},
        {"code", 0},
    };
#endif
    return return_value.dump();
}

static std::string handle_get_thread_info(Server *serv, const std::string &msg) {
    ReactorThread *thread = serv->get_thread(SwooleTG.id);
    std::stringstream ss;
    ss << std::this_thread::get_id();
    json jinfo{
        {"tid", ss.str()},
        {"id", thread->id},
        {"dispatch_count", thread->dispatch_count},
        {"event_num", SwooleTG.reactor->get_event_num()},
        {"timer_num", SwooleTG.timer ? SwooleTG.timer->count() : 0},
    };
    json return_value{
        {"data", jinfo},
        {"code", 0},
    };
    return return_value.dump();
}

static std::string handle_get_manager_info(Server *serv, const std::string &msg) {
    ProcessPool *pool = (ProcessPool *) &serv->gs->event_workers;
    json jinfo{
        {"pid", getpid()},
        {"reload_count", pool->reload_count},
        {"reload_last_time", pool->reload_last_time},
    };
    json return_value{
        {"data", jinfo},
        {"code", 0},
    };
    return return_value.dump();
}

static size_t get_socket_out_buffer_total_size() {
    if (!sw_reactor()) {
        return 0;
    }
    size_t size = 0;
    for (auto s : sw_reactor()->get_sockets()) {
        if (s.second->out_buffer) {
            size += s.second->out_buffer->length();
        }
    }
    return size;
}

static std::string handle_get_memory_info(Server *serv, const std::string &msg) {
    bool is_thread = serv->is_reactor_thread();

    json jinfo{
        {"server", sizeof(Server)},
        {"workers", serv->get_all_worker_num() * sizeof(Worker)},
        {"connection_list", serv->get_max_connection() * sizeof(Connection)},
        {"session_list", SW_SESSION_LIST_SIZE * sizeof(Session)},
        {"global_memory", dynamic_cast<GlobalMemory *>(sw_mem_pool())->get_memory_size()},
        {"thread_global_memory", sw_tg_buffer()->size},
        {"message_bus",
         is_thread ? serv->get_thread(SwooleTG.id)->message_bus.get_memory_size()
                   : serv->message_bus.get_memory_size()},
        {"socket_list", sw_reactor() ? sw_reactor()->get_sockets().size() * sizeof(network::Socket) : 0},
        {"socket_out_buffer", get_socket_out_buffer_total_size()},
        {"php_memory", is_thread ? 0 : zend_memory_usage(true)},
        {"http_buffer", swoole_http_buffer ? swoole_http_buffer->size : 0},
#ifdef SW_HAVE_COMPRESSION
        {"zlib_buffer", swoole_zlib_buffer ? swoole_zlib_buffer->size : 0},
#else
        {"zlib_buffer", 0},
#endif
    };
    json return_value{
        {"data", jinfo},
        {"code", 0},
    };
    return return_value.dump();
}

static std::string handle_get_connections(Server *serv, const std::string &msg) {
    json list = json::array();
    serv->foreach_connection([serv, &list](Connection *conn) {
        if (serv->is_process_mode() && conn->reactor_id != SwooleTG.id) {
            return;
        }
        if (serv->is_base_mode() && SwooleWG.worker && conn->reactor_id != SwooleWG.worker->id) {
            return;
        }
        list.push_back(get_connection_info(serv, conn));
    });
    json return_value{
        {"data", list},
        {"code", 0},
    };
    return return_value.dump();
}

static std::string handle_get_connection_info(Server *serv, const std::string &msg) {
    auto _result = json::parse(msg);
    if (!_result.is_object() || _result.find("session_id") == _result.end()) {
        json return_value{
            {"data", "require parameter session_id"},
            {"code", 4003},
        };
        return return_value.dump();
    }

    std::string _session_id = _result["session_id"];
    int session_id = std::atoi(_session_id.c_str());
    Connection *conn = serv->get_connection_verify(session_id);
    if (!conn) {
        json return_value{
            {"data", "connection not exists"},
            {"code", 4004},
        };
        return return_value.dump();
    }

    json return_value{
        {"data", get_connection_info(serv, conn)},
        {"code", 0},
    };
    return return_value.dump();
}

static std::string handle_get_all_ports(Server *serv, const std::string &msg) {
    json _list = json::array();
    for (auto port : serv->ports) {
        json info = json::object({
            {"host", port->host},
            {"port", port->port},
            {"backlog", port->backlog},
            {"type", port->type},
            {"ssl", port->ssl},
            {"protocols", port->get_protocols()},
            {"connection_num", (long) port->gs->connection_num},
        });
        _list.push_back(info);
    };
    json return_value{
        {"data", _list},
        {"code", 0},
    };
    return return_value.dump();
}

void register_admin_server_commands(Server *serv) {
    serv->add_command("get_all_sockets", Server::Command::ALL_PROCESS, handle_get_all_sockets);
    serv->add_command("get_all_commands", Server::Command::ALL_PROCESS, handle_get_all_commands);
    serv->add_command("get_socket_info", Server::Command::ALL_PROCESS, handle_get_socket_info);
    serv->add_command("get_thread_info", Server::Command::ALL_PROCESS, handle_get_thread_info);
    serv->add_command("get_manager_info", Server::Command::MANAGER, handle_get_manager_info);
    serv->add_command("get_thread_info", Server::Command::ALL_PROCESS, handle_get_thread_info);
    serv->add_command("get_memory_info", Server::Command::ALL_PROCESS, handle_get_memory_info);
    serv->add_command("get_all_unix_sockets", Server::Command::ALL_PROCESS, handle_get_all_unix_sockets);
    serv->add_command("get_all_ports", Server::Command::MASTER, handle_get_all_ports);

    int accepted_process_types;
    if (serv->is_base_mode() || serv->single_thread) {
        accepted_process_types = Server::Command::EVENT_WORKER | Server::Command::MASTER;
    } else {
        accepted_process_types = Server::Command::REACTOR_THREAD;
    }
    serv->add_command("get_connections", accepted_process_types, handle_get_connections);
    serv->add_command("get_connection_info", accepted_process_types, handle_get_connection_info);
}
}  // namespace swoole

typedef std::function<void(zend_object *obj)> objects_store_iterator;

static inline bool object_valid(zend_object *obj) {
    return obj && IS_OBJ_VALID(obj) && obj->handlers && obj->handlers->get_class_name;
}

static void objects_store_foreach(const objects_store_iterator &fn) {
    for (uint32_t i = 0; i < EG(objects_store).top; i++) {
        zend_object *obj = EG(objects_store).object_buckets[i];
        if (object_valid(obj)) {
            fn(obj);
        }
    }
}

static uint32_t object_store_count() {
    uint32_t count = 0;
    objects_store_foreach([&count](zend_object *obj) { count++; });
    return count;
}

ZEND_FUNCTION(swoole_get_vm_status) {
    array_init(return_value);
    add_assoc_long_ex(return_value, ZEND_STRL("object_num"), object_store_count());
    add_assoc_long_ex(return_value, ZEND_STRL("resource_num"), zend_array_count(&EG(regular_list)));
}

ZEND_FUNCTION(swoole_get_objects) {
    zend_objects_store *objects = &EG(objects_store);
    if (objects->top <= 1) {
        RETURN_FALSE;
    }

    array_init(return_value);
    objects_store_foreach([return_value](zend_object *obj) {
        zval zobject;
        ZVAL_OBJ(&zobject, obj);
        zval_addref_p(&zobject);
        add_next_index_zval(return_value, &zobject);
    });
}

ZEND_FUNCTION(swoole_get_object_by_handle) {
    zend_long handle;
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_LONG(handle)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zend_objects_store *objects = &EG(objects_store);
    if (objects->top <= 1 || handle >= objects->top) {
        RETURN_FALSE;
    }

    zend_object *obj = objects->object_buckets[handle];
    if (!object_valid(obj)) {
        RETURN_FALSE;
    }
    GC_ADDREF(obj);
    RETURN_OBJ(obj);
}
