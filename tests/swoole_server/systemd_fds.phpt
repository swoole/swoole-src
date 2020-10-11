--TEST--
swoole_server: systemd fds
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Client;

const UNIX_SOCK_1 = '/tmp/swoole.test.uinx_stream.sock';
const UNIX_SOCK_2 = '/tmp/swoole.test.uinx_dgram.sock';

$pm = new SwooleTest\ProcessManager;
$pm->initFreePorts(4);

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::notEmpty($client->connect("127.0.0.1", $pm->getFreePort(0)));
    $client->send("SUCCESS");
    Assert::eq($client->recv(), 'SUCCESS'.PHP_EOL);
    $client->close();

    $client = new Client(SWOOLE_SOCK_UDP);
    Assert::notEmpty($client->connect("127.0.0.1", $pm->getFreePort(1)));
    $client->send("SUCCESS");
    Assert::eq($client->recv(), 'SUCCESS'.PHP_EOL);
    $client->close();

    $client = new Client(SWOOLE_SOCK_TCP6);
    Assert::notEmpty($client->connect("::1", $pm->getFreePort(2)));
    $client->send("SUCCESS");
    Assert::eq($client->recv(), 'SUCCESS'.PHP_EOL);
    $client->close();

    $client = new Client(SWOOLE_SOCK_UDP6);
    Assert::notEmpty($client->connect("::1", $pm->getFreePort(3), 0.5, 0));
    $client->send("SUCCESS");
    Assert::eq($client->recv(), 'SUCCESS'.PHP_EOL);
    $client->close();

    $client = new Client(SWOOLE_SOCK_UNIX_STREAM);
    Assert::notEmpty($client->connect(UNIX_SOCK_1));
    $client->send("SUCCESS");
    Assert::eq($client->recv(), 'SUCCESS'.PHP_EOL);
    $client->close();

    $client = new Client(SWOOLE_SOCK_UNIX_DGRAM);
    Assert::notEmpty($client->connect(UNIX_SOCK_2));
    $client->send("SUCCESS");
    Assert::eq($client->recv(), 'SUCCESS'.PHP_EOL);
    $client->close();

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $sockets = [];
    $sockets[] = stream_socket_server('tcp://127.0.0.1:'.$pm->getFreePort(0), $errno, $errstr);
    $sockets[] = stream_socket_server('udp://0.0.0.0:'.$pm->getFreePort(1), $errno, $errstr, STREAM_SERVER_BIND);
    $sockets[] = stream_socket_server('tcp://[::1]:'.$pm->getFreePort(2), $errno, $errstr);
    $sockets[] = stream_socket_server('udp://[::]:'.$pm->getFreePort(3), $errno, $errstr, STREAM_SERVER_BIND);
    $sockets[] = stream_socket_server('unix://'.UNIX_SOCK_1, $errno, $errstr);
    $sockets[] = stream_socket_server('udg://'.UNIX_SOCK_2, $errno, $errstr, STREAM_SERVER_BIND);

    putenv('LISTEN_PID='. posix_getpid());
    putenv('LISTEN_FDS='. count($sockets));

    $serv = new Server('SYSTEMD', 0, SWOOLE_BASE);

    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null',]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $serv->on("packet", function (Server $serv, $data, $addr) {
        // var_dump($addr);
        $serv->sendto($addr['address'], isset($addr['port']) ? $addr['port'] : 0, 'SUCCESS'.PHP_EOL);
    });

    $serv->on("receive", function (Server $serv, $fd, $tid, $data) {
        $serv->send($fd, 'SUCCESS'.PHP_EOL);
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();

if (is_file(UNIX_SOCK_1)) {
    unlink(UNIX_SOCK_1);
}
if (is_file(UNIX_SOCK_2)) {
    unlink(UNIX_SOCK_2);
}

?>
--EXPECT--
