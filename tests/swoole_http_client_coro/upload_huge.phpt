--TEST--
swoole_http_client_coro: upload a big file
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('HTTPBIN_LOCALLY');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Http\Client(HTTPBIN_SERVER_HOST, HTTPBIN_SERVER_PORT);
    $cli->set(['timeout' => 10]);
    $content = str_repeat(get_safe_random(IS_IN_TRAVIS ? 16 : 64), 1024 * 1024); // 64M
    file_put_contents('/tmp/test.jpg', $content);
    $cli->addFile('/tmp/test.jpg', 'test.jpg');
    $ret = $cli->post('/post', ['name' => 'twosee']);
    if ($ret) {
        Assert::assert(count($cli->headers) > 0);
        Assert::assert($cli->statusCode === 200);
        $body = json_decode($cli->body, true);
        Assert::assert($body['files']['test.jpg'] === $content);
        echo "SUCCESS\n";
    }
    $cli->close();
    @unlink('/tmp/test.jpg');
});
?>
--EXPECT--
SUCCESS
