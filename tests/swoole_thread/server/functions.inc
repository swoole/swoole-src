<?php
function thread_server_test_eof_client($port)
{
    $cli = new Co\Client(SWOOLE_SOCK_TCP);
    $cli->set([
        'open_eof_check' => true,
        'package_eof' => "\r\n",
    ]);
    Assert::assert($cli->connect('127.0.0.1', $port, 2));
    $cli->send(json_encode(['type' => 'eof']) . "\r\n");
    Assert::eq($cli->recv(), "EOF\r\n");
}
