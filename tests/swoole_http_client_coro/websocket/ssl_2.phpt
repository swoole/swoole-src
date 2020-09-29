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
    $n = 16;
    $cli->push('{"op": "subscribe", "args": ["orderBookL2_25:XBTUSD"]}');
    while ($n--) {
        $frame = $cli->recv();
        if (!$frame or empty($frame->data)) {
            echo "ERROR $n [2]\n";
            var_dump($cli->errCode, $cli->errMsg);
            break;
        }
    }
    echo "FINISH\n";
});
?>
--EXPECT--
CONNECT SUCCESS, StatusCode=101
FINISH
