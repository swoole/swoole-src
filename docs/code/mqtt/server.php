<?php
/**
 * User: lufei
 * Date: 2020/7/21
 * Email: lufei@swoole.com
 */

//composer require simple-swoole/simps

include __DIR__ . '/vendor/autoload.php';

use Simps\Server\Protocol\MQTT;

$server = new Swoole\Server('127.0.0.1', 9501, SWOOLE_BASE);

$server->set([
    'open_mqtt_protocol' => 1, // 启用 MQTT 协议
    'worker_num' => 1,
    'package_max_length' => 30 * 1024 * 1024
]);

$server->on('connect', function ($server, $fd) {
    echo "Client #{$fd}: Connect.\n";
});
$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    try {
        $data = MQTT::decode($data);
        var_dump($data);
        if (is_array($data) && isset($data['cmd'])) {
            switch ($data['cmd']) {
                case MQTT::CONNECT: // 连接
                    // 如果协议名不正确服务端可以断开客户端的连接，也可以按照某些其它规范继续处理CONNECT报文
                    if ($data['protocol_name'] != "MQTT") {
                        $server->close($fd);
                        return false;
                    }

                    // 判断客户端是否已经连接，如果是需要断开旧的连接
                    // 判断是否有遗嘱信息
                    // ...

                    // 返回确认连接请求
                    $server->send($fd, MQTT::getAck([
                                'cmd' => 2, // CONNACK固定值为2
                                'code' => 0, // 连接返回码 0表示连接已被服务端接受
                                'session_present' => 0
                            ]));
                    break;
                case MQTT::PINGREQ: // 心跳请求
                        // 返回心跳响应
                        $server->send($fd, MQTT::getAck(['cmd' => 13]));
                    break;
                case MQTT::DISCONNECT: // 客户端断开连接
                    if ($server->exist($fd)) {
                        $server->close($fd);
                    }
                    break;
                case MQTT::PUBLISH: // 发布消息
                    $server->send(
                        1, // 发给那个客户端 fd
                        MQTT::getAck(
                            [
                                'cmd' => $data['cmd'],
                                'topic' => $data['topic'],
                                'content' => $data['content'],
                                'dup' => $data['dup'],
                                'qos' => $data['qos'],
                                'retain' => $data['retain'],
                                'message_id' => $data['message_id'] ?? ''
                            ]
                        )
                    );
                    break;
                case MQTT::SUBSCRIBE: // 订阅
                    $payload = [];
                    foreach ($data['topics'] as $k => $qos) {
                        if (is_numeric($qos) && $qos < 3) {
                            $payload[] = chr($qos);
                        } else {
                            $payload[] = chr(0x80);
                        }
                    }
                    $server->send(
                        $fd,
                        MQTT::getAck(
                            [
                                'cmd' => 9,
                                'message_id' => $data['message_id'] ?? '',
                                'payload' => $payload
                            ]
                        )
                    );
                    break;
            }
        } else {
            $server->close($fd);
        }
    } catch (\Exception $e) {
        $server->close($fd);
    }
});

$server->on('close', function ($server, $fd) {
    echo "Client #{$fd}: Close.\n";
});

$server->start();