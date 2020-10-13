--TEST--
swoole_server/ssl: nodejs client
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_command_not_found('node');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        $result = Co::exec('node '.__DIR__.'/code/connect.js '.$pm->getFreePort());
        Assert::eq($result['code'], 0);
        Assert::contains($result['output'], 'swoole-http-server');
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("request", function ($request, $response) {
        $response->header("Content-Type", "text/plain");
        $response->end("Hello World\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
