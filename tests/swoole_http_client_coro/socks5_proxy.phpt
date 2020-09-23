--TEST--
swoole_http_client_coro: socks5 proxy
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_socks5_proxy();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function ()
{
    $domain = 'www.google.com';
    $cli = new Swoole\Coroutine\Http\Client($domain, 443, true);

    $cli->setHeaders(['Host' => $domain]);
    $cli->set([
        'timeout'     => 5,
        'socks5_host' => SOCKS5_PROXY_HOST,
        'socks5_port' => SOCKS5_PROXY_PORT,
    ]);

    $ret = $cli->get('/');
    if (!$ret)
    {
        die("ERROR\n");
    }
    Assert::same($cli->statusCode, 200);
    Assert::assert(stripos($cli->body, 'google.com') !== false);
    $cli->close();
});

swoole_event::wait();
?>
--EXPECT--
