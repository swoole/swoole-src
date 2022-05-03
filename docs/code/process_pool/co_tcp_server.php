<?php
/**
 * User: lufei
 * Date: 2020/8/5
 * Email: lufei@swoole.com
 */

//多进程管理模块
$pool = new Swoole\Process\Pool(2);
//让每个OnWorkerStart回调都自动创建一个协程
$pool->set(['enable_coroutine' => true]);
$pool->on('workerStart', function ($pool, $id) {
    //每个进程都监听9501端口
    $server = new Swoole\Coroutine\Server('127.0.0.1', '9501' , false, true);

    //收到15信号关闭服务
    Swoole\Process::signal(SIGTERM, function () use ($server) {
        echo '收到15信号' . PHP_EOL;
        $server->shutdown();
    });

    //接收到新的连接请求 并自动创建一个协程
    $server->handle(function (Swoole\Coroutine\Server\Connection $conn) use ($id) {
        while (true) {
            //接收数据
            $data = $conn->recv();
            if (empty($data)) {
                $conn->close();
                break;
            }

            //发送数据
            $conn->send("server#{$id}：" . $data);

            \Co::sleep(1);
        }
    });

    //开始监听端口
    $server->start();
});
$pool->start();
