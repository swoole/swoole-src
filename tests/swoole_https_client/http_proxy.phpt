--TEST--
swoole_https_client: get
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$cli = new swoole_http_client('www.baidu.com', 443, true);
$cli->setHeaders([
    'Host' => 'www.baidu.com',
    'User-Agent' => 'Chrome/49.0.2587.3',
    'Accept' => 'text/html,application/xhtml+xml,application/xml',
    'Accept-Encoding' => 'gzip',
]);
$cli->set(['http_proxy_host' => HTTP_PROXY_HOST, 'http_proxy_port' => HTTP_PROXY_PORT]);
$cli->get('/', function ($cli)
{
    assert($cli->statusCode == 200);
    echo "SUCCESS\n";
    $cli->close();
});
swoole_event::wait();
?>
--EXPECT--
SUCCESS
