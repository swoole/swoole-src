--TEST--
swoole_http_client_coro: upload a big file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (getenv("SKIP_ONLINE_TESTS")) {
    die("skip online test");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Http\Client(IS_IN_TRAVIS ? 'news.mit.edu' : 'www.cust.edu.cn');
    $cli->set(['timeout' => 30]);
    $content = str_repeat(openssl_random_pseudo_bytes(1024), 5 * 1024);
    file_put_contents('/tmp/test.jpg', $content);
    $cli->addFile('/tmp/test.jpg', 'test.jpg');
    $ret = $cli->post('/', ['name' => 'rango']);
    Assert::assert($ret);
    Assert::assert(count($cli->headers) > 0);
    Assert::same($cli->statusCode, 200);
    Assert::assert(strpos($cli->body, IS_IN_TRAVIS ? 'MIT News' : 'cust.edu.cn') !== false);
    $cli->close();
    @unlink('/tmp/test.jpg');
    echo "DONE\n";
});
?>
--EXPECT--
DONE
