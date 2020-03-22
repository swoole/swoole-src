--TEST--
swoole_server/ssl: dtls with length protocol
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use SwooleTest\ProcessManager;
use Swoole\Atomic;
use Swoole\Client;

$size = rand(8192, 128000);

$req = random_bytes($size);
$resp = random_bytes($size);

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $req, $resp) {
    $cli = new Client(SWOOLE_SOCK_UDP | SWOOLE_SSL, SWOOLE_SOCK_SYNC);
    $cli->set(
        [
            'open_length_check' => true,
            'package_max_length' => 16 * 1024 * 1024,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ]
    );
    $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 1);
    $cli->send(pack('N', strlen($req)) . $req);
    $data = $cli->recv();
    Assert::eq(bin2hex($resp), bin2hex(substr($data, 4)));
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $size, $req, $resp) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_UDP | SWOOLE_SSL);
    $serv->set(
        [
            "worker_num" => 1,
            'log_file' => '/dev/null',
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
            'open_length_check' => true,
            'package_max_length' => 16 * 1024 * 1024,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ]
    );
    $serv->on(
        "WorkerStart",
        function (Server $serv) use ($pm) {
            $pm->wakeup();
        }
    );
    $serv->on(
        "connect",
        function ($serv, $fd, $rid) {
            //echo "connect\n";
        }
    );
    $serv->on(
        "receive",
        function ($serv, $fd, $rid, $data) use ($req, $resp) {
            Assert::eq(bin2hex($req), bin2hex(substr($data, 4)));
            $serv->send($fd, pack('N', strlen($resp)) . $resp);
        }
    );
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
