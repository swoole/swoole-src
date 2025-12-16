--TEST--
swoole_http2_client_coro: max frame size
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (strpos(shell_exec("nghttpd --version 2>&1"), 'nghttp2') === false) {
    skip('no nghttpd');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        co::sleep(0.1);
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->connect();

        $req = new Swoole\Http2\Request;
        $req->path = "/test.jpg";
        Assert::greaterThanEq($cli->send($req), 1);
        $resp = $cli->recv();
        Assert::contains($resp->headers['server'], 'nghttpd');
        Assert::eq($resp->data, file_get_contents(TEST_IMAGE));

        shell_exec("ps -A | grep nghttpd | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1");
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $root = ROOT_DIR . '/examples';
    $pm->wakeup();
    shell_exec("nghttpd -v -d {$root}/ -a 0.0.0.0 {$pm->getFreePort()} --no-tls&");
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
