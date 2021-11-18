<?php
$cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function(Swoole\Client $cli) {
    Assert::true(false, 'never here');
});
$cli->on("receive", function(Swoole\Client $cli, $data) {
    Assert::true(false, 'never here');
});
$cli->on("error", function(Swoole\Client $cli) { echo "connect timeout\n"; });
$cli->on("close", function(Swoole\Client $cli) { echo "close\n"; });
$cli->connect("11.11.11.11", 9000, 0.5);
