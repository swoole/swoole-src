--TEST--
swoole_http_client_coro: http client
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Server;

$pm = new ProcessManager();
$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('WorkerStart', function (Server $serv) {
        /*
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $domain = TEST_DOMAIN_3;
        $cli = new Client($domain, 443, true);
        $cli->set(['timeout' => 10]);
        $cli->setHeaders([
            'Host' => $domain,
            'User-Agent' => TEST_USER_AGENT,
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $ret = $cli->get('/');
        Assert::assert($cli->socket instanceof Socket);
        if (!$ret) {
            $response->end("ERROR\n");
            return;
        }
        $response->end("OK\n");
        $cli->close();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
