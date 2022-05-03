<?php

declare(strict_types=1);
/**
 * This file is part of Simps.
 *
 * @link     https://simps.io
 * @document https://doc.simps.io
 * @license  https://github.com/simple-swoole/simps/blob/master/LICENSE
 */

require __DIR__ . '/vendor/autoload.php';

use Simps\Client\MQTTClient;

$config = [
    'host' => '127.0.0.1',
    'port' => 9501,
    'time_out' => 5,
    'username' => 'user03',
    'password' => 'hLXQ9ubnZGzkzf',
    'client_id' => 'd812edc1-18da-2085-0edf-a4a588c296d1',
    'keepalive' => 10,
];

Co\run(function () use ($config) {
    $client = new MQTTClient($config, ['open_mqtt_protocol' => true, 'package_max_length' => 30 * 1024 * 1024]);
    $will = [
        'topic' => 'swoole-mqtt/user03/update',
        'qos' => 1,
        'retain' => 0,
        'content' => '123',
    ];
    while (! $client->connect(true, $will)) {
        \Swoole\Coroutine::sleep(3);
        $client->connect(true, $will);
    }
    $topics['swoole-mqtt/user03/get'] = 1;
    $topics['swoole-mqtt/user03/update'] = 1;
    $timeSincePing = time();
    $client->subscribe($topics);
    while (true) {
        $buffer = $client->recv();
        var_dump($buffer);
        if ($buffer && $buffer !== true) {
            $timeSincePing = time();
        }
        if (isset($config['keepalive']) && $timeSincePing < (time() - $config['keepalive'])) {
            $buffer = $client->ping();
            if ($buffer) {
                echo '发送心跳包成功' . PHP_EOL;
                $timeSincePing = time();
            } else {
                $client->close();
                break;
            }
        }
    }
});
