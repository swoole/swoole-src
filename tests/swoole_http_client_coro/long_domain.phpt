--TEST--
swoole_http_client_coro: long domain
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function http_get(string $url)
{
    $url_info = parse_url($url);
    $domain = $url_info['host'];
    $cli = new Swoole\Coroutine\Http\Client($domain);
    $cli->set(['timeout' => 5]);
    $cli->setHeaders([
        'Host' => $domain,
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip'
    ]);
    Assert::assert($cli->get('/'));
    Assert::same($cli->statusCode, 200);
    Assert::assert(!empty($cli->body));
}

go(function () {
    http_get('http://888888888888888888888888888888888888888888888888888888888888888.com');
});
go(function () {
    http_get('http://www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com');
});
go(function () {
    http_get('http://www.mamashuojiusuannizhucedeyumingzaichanggoogledounengsousuochulai.cn');
});
?>
--EXPECT--
