--TEST--
swoole_client_coro: send and recv with channel
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $client = new Co\Client(SWOOLE_SOCK_TCP);
        $client->connect("127.0.0.1",  $pm->getFreePort());

        $send_queue = new chan(150);
        $recv_queue = new chan(150);

        //读协程
        go(function () use ($recv_queue, $send_queue, $client) {
            while(true) {
                $data = $client->recv();
                if (empty($data)) {
                    //连接关闭了，结束
                    $send_queue->close();
                    $recv_queue->close();
                    $client->close();
                    break;
                } else {
                    $recv_queue->push($data);
                }
            }
            echo "read-co stop\n";
        });

        //写协程
        go(function () use ($send_queue, $client) {
            while(true) {
                $data = $send_queue->pop();
                if (empty($data)) {
                    //通道已关闭
                    break;
                } else {
                    $client->send($data);
                }
            }
            echo "write-co stop\n";
        });

        //启动 $n 个协程做消费者
        $n = 100;
        while ($n--) {
            go(function () use ($recv_queue, $n) {
                for ($i = 0; $i < 100; $i++) {
                    //收到了数据
                    $data = $recv_queue->pop();
                }
                //echo "consumer-co $n stop\n";
            });
        }

        //启动 $n 个协程随机发送数据
        $n = 100;
        while ($n--) {
            go(function () use ($send_queue, $n) {
                for ($i = 0; $i < 100; $i++) {
                    //投递任务
                    $send_queue->push("hello world $i ".rand(1000000, 9999999)."\r\n");
                }
                //echo "producer $n stop\n";
            });
        }
    });

    swoole_event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        'open_eof_split' => true,
        'package_eof' => "\r\n",
    ]);
    $serv->on("workerStart", function ($serv) use ($pm)
    {
        $pm->wakeup();
    });

    $serv->on('receive', function ($serv, $fd, $tid, $data)
    {
        static $i = 0;
        $serv->send($fd, "Swoole: $data");
        $i++;
        if ($i == 10000) {
            $serv->close($fd);
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
write-co stop
read-co stop
