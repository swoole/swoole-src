--TEST--
swoole_http_client_coro: upload a big file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Http\Client('www.cust.edu.cn', 80);
    $content = str_repeat(openssl_random_pseudo_bytes(1024), 1024 * (IS_IN_TRAVIS ? 1 : 5));
    file_put_contents('/tmp/test.jpg', $content);
    $cli->addFile('/tmp/test.jpg', 'test.jpg');
    $ret = $cli->post('/', ['name' => 'rango']);
    assert($ret);
    assert(count($cli->headers) > 0);
    assert($cli->statusCode === 200);
    assert(strpos($cli->body, 'cust.edu.cn') !== false);
    $cli->close();
    @unlink('/tmp/test.jpg');
});

?>
--EXPECT--
