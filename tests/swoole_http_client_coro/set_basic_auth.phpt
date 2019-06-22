--TEST--
swoole_http_client_coro: http client set basic auth
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Http\Client(HTTPBIN_SERVER_HOST, HTTPBIN_SERVER_PORT);
    $cli->set(['timeout' => 10]);
    $cli->setHeaders([
        'host' => 'httpbin.org',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $username = get_safe_random();
    $password = get_safe_random();
    $cli->setBasicAuth($username, $password);
    $ret = $cli->get("/basic-auth/{$username}/{$password}");
    if ($ret && !empty($cli->statusCode === 200)) {
        echo "OK\n";
    } else {
        echo "ERROR\n";
    }
});
Swoole\Event::wait();
?>
--EXPECT--
OK
