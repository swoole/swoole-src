--TEST--
swoole_coroutine: http client with HEAD method
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

Swoole\Coroutine::create(function ()
{
    $cli = new \Swoole\Coroutine\Http\Client('www.baidu.com', 80);
    $cli->set(['timeout' => 1]);
    $cli->setMethod("HEAD");
    $cli->get('/');
    assert($cli->statusCode == 200);
    assert(count($cli->headers) > 0);
});
?>
--EXPECT--

