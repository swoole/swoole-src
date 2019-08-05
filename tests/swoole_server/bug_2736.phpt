--TEST--
swoole_server: bug Github#2736
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
        $client->set(['timeout' => 2, 'open_eof_check' => true, 'package_eof' => "\r\n"]);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $i = 230;
        $data = "hello world-" . str_repeat('A', $i) . '- BB';
        $package_length = pack('N', strlen($data));
        $array = str_split($package_length . $data, 100);
        foreach ($array as $value) {
            $client->send($value);
        }
        $data = $client->recv();
        Assert::assert($data);
        echo "DONE\n";
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'ssl_cert_file' => dirname(__DIR__) . '/include/api/ssl-ca/server-cert.pem',
        'ssl_key_file' => dirname(__DIR__) . '/include/api/ssl-ca/server-key.pem',
        'open_length_check' => true,
        'package_max_length' => 2097152,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'log_file' => TEST_LOG_FILE,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
        $_k = unpack('Nlen', substr($data, 0, 4));
        $len = $_k['len'];
        $body = substr($data, 4);
        $serv->send($fd, json_encode(['len' => $len, 'body' => $body]) . "\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
