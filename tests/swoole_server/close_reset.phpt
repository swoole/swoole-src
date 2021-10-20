--TEST--
swoole_server: close with reset
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;
use Swoole\Timer;
use Swoole\Coroutine\Client;

$pm = new SwooleTest\ProcessManager;

const N = 4 * 1024 * 1024;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->set(['socket_buffer_size' => 128 * 1024]);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("close");
        Co::sleep(1);
        $data = '';

        while (true) {
            $ret = $client->recv();
            if (empty($ret)) {
                break;
            }
            $data .= $ret;
            if (substr($ret, -2, 2) == "\r\n") {
                break;
            }
        }
        Assert::lessThan(strlen($data), N);
        echo "DONE\n";
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        'worker_num' => 1,
        'log_file' => TEST_LOG_FILE,
        'kernel_socket_send_buffer_size' => 128 * 1024,
        'socket_buffer_size' => 8 * 1024 * 1024,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
        $serv->send($fd, str_repeat('A', N) . "\r\n");
        Assert::eq($serv->stats()['connection_num'], 1);
        phpt_var_dump("close[0]");
        Assert::true($serv->close($fd));
        usleep(50000);
        phpt_var_dump("close[1]");
        Assert::false($serv->close($fd));
        Assert::eq(swoole_last_error(), SWOOLE_ERROR_SESSION_CLOSED);
        Assert::eq($serv->stats()['connection_num'], 1);
        Timer::after(100, function () use ($fd, $serv) {
            phpt_var_dump("close[2]");
            $serv->close($fd, true);
            usleep(50000);
            Assert::eq($serv->stats()['connection_num'], 0);
        });
    });
    $serv->on(Constant::EVENT_CLOSE, function (Server $serv, $fd, $reactor_id) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
