--TEST--
swoole_server/ssl: send_wait support ssl
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm)  {
        $client = new Client('127.0.0.1', $pm->getFreePort(), true);

        $ret = $client->get('/');
        Assert::eq('swoole', $client->body);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);

    $server->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        'ssl_ciphers' => 'ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP',
        'ssl_protocols' => defined('SWOOLE_SSL_SSLv3') ? SWOOLE_SSL_SSLv3 : 0,
        'ssl_verify_peer' => false,
        'ssl_allow_self_signed' => true,
    ]);

    $server->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });

    $server->on('Receive', function (Server $s, int $clientId, int $threadId, string $data) use ($server) {
        $message = "HTTP/1.1 200 OK\r\nContent-Length:6\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nswoole";
        $server->sendwait($clientId, $message);
    });

    $server->start();

};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
