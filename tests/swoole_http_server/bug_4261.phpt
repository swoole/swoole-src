--TEST--
swoole_http_server: bug Github#4261
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $uuid = urlencode(uniqid('swoole'));
    $port = $pm->getFreePort();
    $out = shell_exec("curl -sS --location --request POST 'http://127.0.0.1:{$port}' -H 'Content-Type:multipart/form-data;charset=UTF-8' --form 'token=$uuid'");
    Assert::contains($out, $uuid);
    $pm->kill();
    echo "SUCCESS\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->end(var_export($request->post, true));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
SUCCESS
