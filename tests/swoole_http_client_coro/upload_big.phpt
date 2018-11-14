--TEST--
swoole_http_client_coro: upload a big file
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function() {
	$cli = new Swoole\Coroutine\Http\Client('www.swoole.com', 80);
	$cli->addFile(TEST_BIG_IMAGE, 'test.jpg');
	$ret = $cli->post('/index.php', array('name' => 'rango'));
    assert($ret);
    assert(count($cli->headers) > 0);
    assert($cli->statusCode > 0);
	$cli->close();
});

?>
--EXPECT--
