<?php
/**
 * User: lufei
 * Date: 2020/8/5
 * Email: lufei@swoole.com
 */

Co\run(function () {
    $server = new Swoole\Coroutine\Server('127.0.0.1', '9501');

    //接收到新的连接请求 并自动创建一个协程
    $server->handle(function (Swoole\Coroutine\Server\Connection $conn) {
        while (true) {
            //接收数据
            $data = $conn->recv();
            if (empty($data)) {
                $conn->close();
                break;
            }

            //发送数据
            $conn->send("server：" . $data);

            \Co::sleep(1);
        }
    });

    //开始监听端口
    $server->start();
});