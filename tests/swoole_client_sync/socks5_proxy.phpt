--TEST--
swoole_client_sync: HTTP client with a local SOCKS5 proxy
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require TESTS_API_PATH . '/swoole_client/http_get.php';
require TESTS_API_PATH . '/swoole_client/socks5_fake_proxy.php';

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_TCP);
    $client->set(['socks5_host' => '127.0.0.1', 'socks5_port' => $pm->getFreePort()]);
    client_http_v10_get($client, 'socks5-target.test');
    $client->close();
};
$pm->childFunc = function () use ($pm) {
    socks5_run_proxy($pm, $pm->getFreePort(), false, false, function ($socket) {
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $data = fread($socket, 8192);
            Assert::notEmpty($data);
            $request .= $data;
        }
        Assert::contains($request, "Host: socks5-target.test\r\n");
        $body = 'https://github.com/requests/httpbin';
        fwrite($socket, "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
