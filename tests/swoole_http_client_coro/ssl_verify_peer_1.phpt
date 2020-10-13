--TEST--
swoole_http_client_coro: ssl_verify_peer [1]
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_openssl_version_lower_than('1.1.0');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Coroutine\Http\Client;

$pm = new SwooleTest\ProcessManager;

Co::set(['log_level' => SWOOLE_LOG_WARNING]);

define('SSL_DIR', realpath(__DIR__.'/../../examples/ssl'));

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        //allow_self_signed
        $client = new Client('127.0.0.1', $pm->getFreePort(), true);
        $client->set([
            'ssl_verify_peer' => true,
            'ssl_allow_self_signed' => true,
        ]);
        $client->setHeaders([
            'Host' => "localhost",
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $result = $client->get("/");
        Assert::eq($result, true);
        Assert::eq($client->getBody(), "OK");

        //no allow_self_signed
        $client = new Client('127.0.0.1', $pm->getFreePort(), true);
        $client->set([
            'ssl_verify_peer' => true,
            'ssl_allow_self_signed' => false,
        ]);
        $client->setHeaders([
            'Host' => "localhost",
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $result = $client->get("/");
        Assert::eq($result, false);
        Assert::eq($client->getStatusCode(), -1);
        Assert::eq($client->errCode, SWOOLE_ERROR_SSL_VERIFY_FAILED);
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_DIR . '/ssl.crt',
        'ssl_key_file' => SSL_DIR . '/ssl.key',
    ]);
    $server->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) {
        $response->end('OK');
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
