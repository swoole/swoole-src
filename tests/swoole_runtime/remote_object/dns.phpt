--TEST--
swoole_runtime/remote_object: dns
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_in_ci('failure');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;

run(function ()  {
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
});
?>
--EXPECTF--
