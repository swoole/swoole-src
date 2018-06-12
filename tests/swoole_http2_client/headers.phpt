--TEST--
headers: http2 auto to lower
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
$domain = 'www.swoole.com';
$client = new Swoole\Http2\Client($domain, 443, true);
$client->set([
    'timeout' => 5,
    'ssl_host_name' => $domain
]);
// auto to-lower
$client->setHeaders([
    'Host' => $domain,
    'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36',
    'Accept' => 'text/html,application/xhtml+xml,application/xml',
    'Accept-Encoding' => 'gzip'
]);
$client->get('/', function (Swoole\Http2\Response $response) use ($client) {
    echo $response->statusCode;
    $client->close();
});
swoole_event_wait();
?>
--EXPECT--
200