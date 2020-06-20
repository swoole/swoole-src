--TEST--
swoole_socket_coro: recvAll
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->initRandomDataArray(4, 512 * 1024);

const CASE_LIST = '4';

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($conn->connect('127.0.0.1', $pm->getFreePort()));
        /**
         * Case1，第一次接收到少量內容，随后分多次触发可读事件接收更多数据片
         */
        if (swoole_string(CASE_LIST)->split(',')->contains(1, false)) {
            $conn->send("case-1");
            Co::sleep(0.001);
            $header = $conn->recvAll(4);
            $len = unpack('Nlen', $header)['len'];
            $body = $conn->recvAll($len);
            Assert::eq($body, $pm->getRandomDataElement(0));
        }
        /**
         * Case2，第一次未接收到任何内容，返回 EAGAIN，监听可读，随后分多次触发可读事件接收更多数据片
         */
        if (swoole_string(CASE_LIST)->split(',')->contains(2, false)) {
            $conn->send("case-2");
            $header = $conn->recvAll(4);
            $len = unpack('Nlen', $header)['len'];
            $body = $conn->recvAll($len);
            Assert::eq($body, $pm->getRandomDataElement(1));
        }
        /**
         * Case3，第一次收到少量内容，第二次服务端关闭连接
         */
        if (swoole_string(CASE_LIST)->split(',')->contains(3, false)) {
            $conn->send("case-3");
            Co::sleep(0.001);
            $header = $conn->recvAll(4);
            $len = unpack('Nlen', $header)['len'];
            $body = $conn->recvAll($len);
            Assert::eq($body, substr($pm->getRandomDataElement(2), 0,1024));
        }
        /**
         * Case4，接收4次，第5次服务端关闭连接
         */
        if (swoole_string(CASE_LIST)->split(',')->contains(4, false)) {
            $conn->send("case-4");
            Co::sleep(0.001);
            $header = $conn->recvAll(4);
            $len = unpack('Nlen', $header)['len'];
            $body = $conn->recvAll($len);
            Assert::eq($body, substr($pm->getRandomDataElement(3), 0, 65536 * 3));
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function (Swoole\Server $server, $fd, $rid, $data) use ($pm) {
        if ($data == 'case-1') {
            $body = $pm->getRandomDataElement(0);
            $data = pack('N', strlen($body)) . $body;
            $server->send($fd, substr($data, 0, 1024));
            usleep(40000);
            $server->send($fd, substr($data, 1024));
        } elseif ($data == 'case-2') {
            $body = $pm->getRandomDataElement(1);
            $server->send($fd, pack('N', strlen($body)));
            usleep(40000);
            $server->send($fd, $body);
        } elseif ($data == 'case-3') {
            $body = $pm->getRandomDataElement(2);
            $server->send($fd, pack('N', strlen($body)));
            $server->send($fd, substr($body, 0, 1024));
            usleep(40000);
            $server->close($fd);
        } elseif ($data == 'case-4') {
            $body = $pm->getRandomDataElement(3);
            $server->send($fd, pack('N', strlen($body)));
            for ($i = 0; $i < 3; $i++) {
                $server->send($fd, substr($body, $i * 65536, 65536));
                usleep(40000);
            }
            $server->close($fd);
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
