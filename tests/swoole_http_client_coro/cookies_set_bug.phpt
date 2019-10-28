--TEST--
swoole_http_client_coro: cookies set bug
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function getCookies()
{
    $result = [];
    var_dump($result); // must be empty array
    return $result;
}

go(function () {
    $url_info = parse_url('http://httpbin.org/cookies/set/a/1');
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

    // first request
    $cookies = getCookies();
    $cli->setCookies($cookies);

    Assert::assert($cli->get($path));

    // second request
    $cookies = getCookies();
    $cli->setCookies($cookies);

    Assert::assert($cli->get('/cookies'));
});

?>
--EXPECTF--
array(0) {
}
array(0) {
}
