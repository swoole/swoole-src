--TEST--
swoole_coroutine: httpclient with http_proxy
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/swoole.inc';

go(function () {
    $host = 'www.google.com';
    $cli = new co\http\client($host, 80);
    $cli->setHeaders(['Host' => $host]);
    $cli->set(['http_proxy_host' => HTTP_PROXY_HOST, 'http_proxy_port' => HTTP_PROXY_PORT]);
    $cli->get('/');
    assert($cli->statusCode == 200);
    assert(stripos($cli->body, '<title>Google</title>') !== false);
    $cli->close();
});
?>
--EXPECT--