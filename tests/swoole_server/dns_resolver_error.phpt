--TEST--
swoole_server: unreachable DNS server must not make the worker spin in epoll (EPOLLERR on the c-ares socket)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
ob_start();
(new ReflectionExtension('swoole'))->info();
if (strpos(ob_get_clean(), 'c-ares') === false) {
    exit('skip c-ares support is not enabled');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\Run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        Assert::assert($cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 5));
        $cli->send("lookup");
        echo $cli->recv();
        $cli->send("shutdown");
        $cli->close();
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $rid, $data) {
        if (trim($data) == 'shutdown') {
            $serv->shutdown();
            return;
        }
        // nothing listens on this UDP port: the connected resolver socket gets ECONNREFUSED (EPOLLERR)
        Coroutine::set(['dns_server' => '127.0.0.1:1']);
        $cpu = function () {
            $ru = getrusage();
            return $ru['ru_utime.tv_sec'] + $ru['ru_utime.tv_usec'] / 1e6 + $ru['ru_stime.tv_sec'] + $ru['ru_stime.tv_usec'] / 1e6;
        };
        $cpu_begin = $cpu();
        $ip = Coroutine::dnsLookup('swoole-dns-error.test', 1);
        $cpu_used = $cpu() - $cpu_begin;
        // a spinning reactor burns about one CPU-second per second of the 1s lookup timeout
        $serv->send($fd, ($ip === false ? "LOOKUP FAILED\n" : "UNEXPECTED RESULT\n") . ($cpu_used < 0.3 ? "NO SPIN\n" : "SPIN: {$cpu_used}s CPU\n"));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
$pm->kill();
?>
--EXPECT--
LOOKUP FAILED
NO SPIN
