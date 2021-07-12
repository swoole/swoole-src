--TEST--
swoole_coroutine: gethostbyname and dns cache
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use  Swoole\Coroutine\System;
use  Swoole\Coroutine;

use function Swoole\Coroutine\run;

run(function () {
    $map = IS_IN_TRAVIS ? [
        'www.google.com' => null,
        'www.youtube.com' => null,
        'www.facebook.com' => null,
    ] : [
        'www.baidu.com' => null,
        'www.taobao.com' => null,
        'www.qq.com' => null,
    ];

    $first_time = microtime(true);
    for ($n = MAX_CONCURRENCY_LOW; $n--;) {
        foreach ($map as $host => &$ip) {
            $ip = System::gethostbyname($host);
            Assert::assert(preg_match(IP_REGEX, $ip));
        }
    }
    unset($ip);
    $first_time = microtime(true) - $first_time;
    phpt_var_dump($map);

    $cache_time = microtime(true);
    for ($n = MAX_CONCURRENCY_LOW; $n--;) {
        foreach ($map as $host => $ip) {
            $_ip = System::gethostbyname($host);
            Assert::same($ip, $_ip);
        }
    }
    $cache_time = microtime(true) - $cache_time;

    $no_cache_time = microtime(true);
    for ($n = MAX_CONCURRENCY_LOW; $n--;) {
        swoole_clear_dns_cache();
        $ip = System::gethostbyname(array_rand($map));
        Assert::assert(preg_match(IP_REGEX, $ip));
    }
    $no_cache_time = microtime(true) - $no_cache_time;

    $chan = new Chan(MAX_CONCURRENCY_LOW);
    $no_cache_multi_time = microtime(true);
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        go(function () use ($map, $chan) {
            swoole_clear_dns_cache();
            $ip = System::gethostbyname(array_rand($map));
            Assert::assert(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
            $chan->push(Assert::assert(preg_match(IP_REGEX, $ip)));
        });
    }
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        $chan->pop();
    }
    $no_cache_multi_time = microtime(true) - $no_cache_multi_time;

    phpt_var_dump($first_time, $cache_time, $no_cache_time, $no_cache_multi_time);
    if (!IS_IN_TRAVIS) {
        Assert::assert($cache_time < 0.01);
        Assert::assert($cache_time < $first_time);
        Assert::assert($cache_time < $no_cache_time);
        Assert::assert($cache_time < $no_cache_multi_time);
        Assert::assert($no_cache_multi_time < $no_cache_time);
    }
});
?>
--EXPECTF--
