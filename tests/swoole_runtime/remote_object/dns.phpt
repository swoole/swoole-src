--TEST--
swoole_runtime/remote_object: dns
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

require __DIR__ . '/server.inc';

remote_object_test(function ($client, $socket) {
    $previous                                        = SwooleLibrary::$remote_object_server_socket_file;
    SwooleLibrary::$remote_object_server_socket_file = 'unix://' . $socket;
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    try {
        Assert::true(checkdnsrr('www.baidu.com', 'A'));
        Assert::true(dns_check_record('www.baidu.com', 'A'));

        Assert::true(checkdnsrr('qq.com', 'MX'));
        $mxhosts = [];
        Assert::true(getmxrr('qq.com', $mxhosts));
        Assert::greaterThanEq(count($mxhosts), 1);

        Assert::true(getmxrr('qq.com', $mxhosts, $mxweights));
        Assert::greaterThanEq(count($mxweights), 1);

        $rs = dns_get_record('www.baidu.com', DNS_A);
        Assert::greaterThanEq(count($rs), 1);
        Assert::eq(gethostbyaddr('127.0.0.1'), 'localhost');
    } finally {
        SwooleLibrary::$remote_object_server_socket_file = $previous;
    }
});
?>
--EXPECTF--
