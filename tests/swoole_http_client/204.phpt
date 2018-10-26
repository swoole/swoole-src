--TEST--
swoole_http_client: http 204 no content
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$url_info = parse_url('http://httpbin.org/status/204');
$domain = $url_info['host'];
$path = $url_info['path'];
$cli = new Swoole\Http\Client($domain);
$cli->set(['timeout' => 5]);
$cli->setHeaders([
    'Host' => $domain,
    'User-Agent' => 'Chrome/49.0.2587.3',
    'Accept' => 'text/html,application/xhtml+xml,application/xml',
    'Accept-Encoding' => 'gzip'
]);
assert($cli->post($path, [], function (Swoole\Http\Client $cli) {
    assert($cli->statusCode === 204);
    assert(empty($cli->body));
    $cli->close();
}));

?>
--EXPECT--

