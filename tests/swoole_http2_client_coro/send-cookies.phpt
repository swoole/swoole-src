--TEST--
swoole_http2_client_coro: nghttp2 big data with ssl
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (strpos(`nghttpd --version 2>&1`, 'nghttp2') === false) {
    skip('no nghttpd');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        co::sleep(0.1);
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->connect();

        $filename = pathinfo(__FILE__, PATHINFO_BASENAME);
        $req = new Swoole\Http2\Request;
        $req->path = "/{$filename}";
        $req->cookies = [
            'foo' => 'bar',
            'bar' => 'char'
        ];
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert($cli->send($req));
            $response = $cli->recv(1);
            Assert::same($response->data, co::readFile(__FILE__));
        }
        `ps -A | grep nghttpd | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1`;
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $root = __DIR__;
    `nghttpd -v -d {$root}/ -a 0.0.0.0 {$pm->getFreePort()} --no-tls&`;
    $pm->wakeup();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
