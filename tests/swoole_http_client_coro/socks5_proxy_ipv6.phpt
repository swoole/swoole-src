--TEST--
swoole_http_client_coro: socks5 proxy with IPv6
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_socks5_proxy();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    $domain = 'www.qq.com';
    $ipv6 = System::gethostbyname($domain, AF_INET6);
    $client = new Client($ipv6, 443, true);
    $client->setHeaders([
        'Host' => $domain,
    ]);

    $client->set([
        'ssl_host_name' => $domain,
        'socks5_host' => SOCKS5_PROXY_HOST,
        'socks5_port' => SOCKS5_PROXY_PORT,
    ]);

    Assert::true($client->get('/'));
    $json = json_decode($client->body);
    Assert::eq($json->code, 403);
    $client->close();
});
?>
--EXPECT--
