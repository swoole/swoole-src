--TEST--
swoole_http_client_coro/websocket: ssl recv [2]
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

//Co::set(['log_level' => SWOOLE_LOG_TRACE, 'trace_flags' => SWOOLE_TRACE_ALL]);

Co\run(function ()  {
    $cli = new Co\http\Client('www.bitmex.com', 443, true);
    if (($http_proxy_conf = getenv('https_proxy'))) {
        $uri = parse_url($http_proxy_conf);
        $cli->set([
            'socks5_host' => $uri['host'],
            'socks5_port' => $uri['port'],
        ]);
    }
    $ret = $cli->upgrade('/realtime');
    if (!$ret) {
        echo "ERROR\n";
        return;
    }
    echo "CONNECT SUCCESS, StatusCode={$cli->getStatusCode()}\n";
    $cli->push('{"op": "subscribe", "args": ["orderBookL2_25:XBTUSD"]}');

    $subscribed = $snapshot = false;
    while (!$subscribed || !$snapshot) {
        $frame = $cli->recv();
        Assert::true(is_object($frame));
        Assert::notEmpty($frame->data);
        $message = json_decode($frame->data, true);
        $subscribed = $subscribed || ($message['success'] ?? false);
        $snapshot = $snapshot || (($message['table'] ?? null) === 'orderBookL2_25'
            && ($message['action'] ?? null) === 'partial');
    }
    echo "FINISH\n";
});
?>
--EXPECT--
CONNECT SUCCESS, StatusCode=101
FINISH
