--TEST--
swoole_http_client_coro: invalid file offset and length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $client = new Swoole\Coroutine\Http\Client('127.0.0.1', 1);

    Assert::false(@$client->addFile(TEST_IMAGE, 'test.jpg', null, null, -1));
    Assert::false(@$client->addFile(TEST_IMAGE, 'test.jpg', null, null, 0, -1));
    Assert::false(@$client->download('/', '/tmp/swoole-http-download-invalid', -1));
});
?>
--EXPECT--
