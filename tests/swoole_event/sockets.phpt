--TEST--
swoole_event: add event after server start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Event;

const N = 10;
const GREETING_MESSAGE = 'hi swoole';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die("Unable to create socket\n");
    socket_set_nonblock($socket) or die("Unable to set nonblock on socket\n");

    function socket_onRead($socket)
    {
        static $i = 0;
        $line = socket_read($socket, 8192);
        if (!$line) {
            exit("ERROR\n");
        }
        Assert::eq($line, "Swoole: " . GREETING_MESSAGE);
        if ($i > 10) {
            echo "DONE\n";
            Event::del($socket);
            socket_close($socket);
        } else {
            usleep(10000);
            $i++;
            Event::set($socket, null, 'socket_onWrite', SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE);
        }
    }

    function socket_onWrite($socket)
    {
        socket_write($socket, GREETING_MESSAGE);
        Event::set($socket, null, null, SWOOLE_EVENT_READ);
    }

    function socket_onConnect($socket)
    {
        $err = socket_get_option($socket, SOL_SOCKET, SO_ERROR);
        if ($err == 0) {
            echo "CONNECTED\n";
            Event::set($socket, null, 'socket_onWrite', SWOOLE_EVENT_READ);
            socket_write($socket, GREETING_MESSAGE);
        } else {
            echo "connect server failed\n";
            Event::del($socket);
            socket_close($socket);
        }
    }

    Event::add($socket, 'socket_onRead', 'socket_onConnect', SWOOLE_EVENT_WRITE);
    socket_connect($socket, '127.0.0.1', $pm->getFreePort());
    Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'log_file' => '/dev/null',
    ));
    $serv->on("start", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
        $serv->send($fd, "Swoole: $data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
CONNECTED
DONE
