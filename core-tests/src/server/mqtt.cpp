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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"

#include "swoole_server.h"
#include "swoole_memory.h"
#include "swoole_signal.h"
#include "swoole_lock.h"
#include "swoole_util.h"

using namespace std;
using namespace swoole;

enum MqttPacketType {
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    SUBSCRIBE = 8,
    SUBACK = 9,
    DISCONNECT = 14,
};

std::string current_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    time_t t = system_clock::to_time_t(now);
    char buf[64];
    struct tm tm_now;
    localtime_r(&t, &tm_now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);
    return std::string(buf);
}

struct MqttSession {
    SessionId fd;
    bool subscribed = false;
    uint16_t count = 0;
    uint16_t packet_id_subscribe = 0;
    std::string subscribed_topic;
    Server *server;

    MqttSession(Server *_server, SessionId fd_) : fd(fd_), server(_server) {}

    // 发送 CONNACK 报文，简单实现：Session Present=0, Connect Return code=0 (Success)
    bool send_connack() {
        uint8_t connack[] = {
            0x20,
            0x02,  // 固定报头：CONNACK, 剩余长度2
            0x00,  // Session Present = 0
            0x00   // Connect return code = 0 (成功)
        };
        return server->send(fd, connack, sizeof(connack));
    }

    // 发送 SUBACK 报文，确认订阅成功
    bool send_suback(uint16_t packet_id) {
        uint8_t suback[] = {
            0x90,
            0x03,  // 固定报头：SUBACK, 剩余长度3
            uint8_t(packet_id >> 8),
            uint8_t(packet_id & 0xFF),  // 报文标识符
            0x00                        // 返回码：0x00 QoS 0
        };
        return server->send(fd, suback, sizeof(suback));
    }

    // 发送 PUBLISH 报文，QoS 0 简化，无标识符
    bool send_publish(const std::string &topic, const std::string &message) {
        // PUBLISH fixed header: 0x30 (QoS0), 剩余长度计算
        // variable header: topic (2字节长度 + 字符串)
        uint16_t topic_len = topic.size();
        size_t var_header_len = 2 + topic_len;
        size_t payload_len = message.size();
        size_t remaining_length = var_header_len + payload_len;

        std::vector<uint8_t> packet;
        packet.push_back(0x30);  // PUBLISH, QoS0

        // MQTT剩余长度使用可变长度编码，这里实现简单编码（长度<128假定）
        if (remaining_length < 128) {
            packet.push_back(uint8_t(remaining_length));
        } else {
            // 简单处理大于127的长度，实际可以完善
            do {
                uint8_t byte = remaining_length % 128;
                remaining_length /= 128;
                if (remaining_length > 0) byte |= 0x80;
                packet.push_back(byte);
            } while (remaining_length > 0);
        }

        // variable header topic
        packet.push_back(uint8_t(topic_len >> 8));
        packet.push_back(uint8_t(topic_len & 0xFF));
        packet.insert(packet.end(), topic.begin(), topic.end());

        // payload
        packet.insert(packet.end(), message.begin(), message.end());

        return server->send(fd, packet.data(), packet.size()) == (ssize_t) packet.size();
    }

    bool send_puback(uint16_t packet_id) {
        uint8_t puback[] = {0x40, 0x02, uint8_t(packet_id >> 8), uint8_t(packet_id & 0xFF)};
        return server->send(fd, puback, sizeof(puback));
    }

    bool send_disconnect() {
        uint8_t disconnect[] = {0xE0, 0x00};
        return server->send(fd, disconnect, sizeof(disconnect));
    }

    bool process_packet(const uint8_t *data, size_t len) {
        uint8_t packet_type = (data[0] >> 4);
        switch (packet_type) {
        case CONNECT: {
            std::cout << "收到 CONNECT 报文\n";
            // 简化：收到CONNECT直接回复CONNACK成功
            return send_connack();
        }
        case SUBSCRIBE: {
            std::cout << "收到 SUBSCRIBE 报文\n";
            // SUBSCRIBE 报文结构：固定头 + 剩余长度 + 报文标识符 (2bytes) + Payload
            // 简化解析报文标识符和第一个订阅主题
            if (len < 5) return false;
            uint16_t packet_id = (data[2] << 8) | data[3];
            packet_id_subscribe = packet_id;

            size_t pos = 4;
            if (pos + 2 > len) return false;
            uint16_t topic_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (pos + topic_len > len) return false;
            subscribed_topic.assign((const char *) (data + pos), topic_len);
            std::cout << "订阅主题: " << subscribed_topic << std::endl;

            subscribed = true;
            return send_suback(packet_id);
        }
        case PUBLISH: {
            std::cout << "收到 PUBLISH 报文\n";

            uint8_t flags = data[0] & 0x0F;
            uint8_t qos = (flags & 0x06) >> 1;

            // TODO 需可变长度解析
            size_t remaining_length = data[1];
            EXPECT_GT(remaining_length, 2);

            size_t pos = 2;
            if (pos + 2 > len) return false;

            uint16_t topic_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (pos + topic_len > len) return false;

            std::string topic((const char *) (data + pos), topic_len);
            pos += topic_len;

            uint16_t packet_id = 0;
            if (qos > 0) {
                if (pos + 2 > len) return false;
                packet_id = (data[pos] << 8) | data[pos + 1];
                pos += 2;
            }

            if (pos > len) return false;

            std::string payload((const char *) (data + pos), len - pos);

            std::cout << "主题: " << topic << ", 消息体: " << payload << ", QoS: " << (int) qos << std::endl;

            // 根据需要处理 payload 内容
            // 例如转发给其他客户端、存储等

            // QoS1需要发送PUBACK确认
            if (qos == 1) {
                return send_puback(packet_id);
            }

            // QoS0直接返回成功
            return true;
        }
        // 你可以增加 PINGREQ、DISCONNECT 等消息处理
        default: {
            std::cout << "收到未处理的包类型: " << (int) packet_type << std::endl;
            return true;
        }
        }
    }
};

static void test_mqtt_server(function<void(Server *)> fn) {
    thread child_thread;
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.enable_reuse_port = true;
    serv.private_data_2 = (void *) &fn;

    sw_logger()->set_level(SW_LOG_WARNING);

    std::unordered_map<SessionId, MqttSession *> sessions;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 9501);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_mqtt_protocol = 1;

    serv.create();

    serv.onWorkerStart = [&child_thread](Server *serv, Worker *worker) {
        function<void(Server *)> fn = *(function<void(Server *)> *) serv->private_data_2;
        child_thread = thread(fn, serv);
    };

    serv.onClose = [&sessions](Server *serv, DataHead *info) -> void {
        delete sessions[info->fd];
        sessions.erase(info->fd);
    };

    serv.onConnect = [&sessions](Server *serv, DataHead *info) -> void {
        auto session = new MqttSession(serv, info->fd);
        sessions[info->fd] = session;
        swoole_timer_tick(100, [session, serv](auto r1, TimerNode *tnode) {
            if (session->subscribed) {
                std::string ts = current_timestamp();
                session->send_publish(session->subscribed_topic,
                                      "Index: " + std::to_string(session->count) + ", Time: " + ts);
                session->count++;
                if (session->count > 10) {
                    session->send_disconnect();
                    serv->close(session->fd, false);
                    swoole_timer_del(tnode);
                }
            }
        });
    };

    serv.onReceive = [&sessions](Server *serv, RecvData *req) -> int {
        auto session = sessions[req->info.fd];
        if (!session->process_packet((uint8_t *) req->data, req->info.len)) {
            std::cerr << "处理数据包失败，关闭连接\n";
        }
        return SW_OK;
    };

    serv.start();
    child_thread.join();
}

TEST(mqtt, echo) {
    test_mqtt_server([](Server *serv) {
        swoole_signal_block_all();
        EXPECT_EQ(test::exec_js_script("mqtt.js", std::to_string(serv->get_primary_port()->get_port())), 0);
        kill(serv->get_master_pid(), SIGTERM);
    });

    File fp(TEST_LOG_FILE, O_RDONLY);
    EXPECT_TRUE(fp.ready());
    auto str = fp.read_content();
    SW_LOOP_N(10) {
        ASSERT_TRUE(
            str->contains("received message, topic: test/topic, content: Index: " + std::to_string(i) + ", Time: "));
    }
    unlink(TEST_LOG_FILE);
}
