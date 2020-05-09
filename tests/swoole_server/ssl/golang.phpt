--TEST--
swoole_server/ssl: golang client
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
$dir = __DIR__.'/code';
chdir($dir);
`go build -o go_client client.go >/dev/null 2>&1`;
skip_if_file_not_exist( __DIR__.'/code/go_client');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

define('GO_CLIENT', __DIR__.'/code/go_client');

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        $result = Co::exec(GO_CLIENT.' '.$pm->getFreePort());
        Assert::eq($result['code'], 0);
        Assert::contains($result['output'], 'swoole-http-server');
    });
    $pm->kill();
    unlink(GO_CLIENT);
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
