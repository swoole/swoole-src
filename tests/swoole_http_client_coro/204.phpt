--TEST--
swoole_http_client_coro: http 204 no content
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $url_info = parse_url('http://httpbin.org/status/204');
    $domain = $url_info['host'];
    $path = $url_info['path'];
    $cli = new Swoole\Coroutine\Http\Client($domain);
    $cli->set(['timeout' => 5]);
    $cli->setHeaders([
        'Host' => $domain,
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip'
    ]);
    Assert::assert($cli->post($path, []));
    Assert::same($cli->statusCode, 204);
    Assert::assert(empty($cli->body));
});

?>
--EXPECT--
