--TEST--
swoole_coroutine: gethostbyname and dns cache
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $map = IS_IN_TRAVIS ? [
        'www.google.com' => null,
        'www.youtube.com' => null,
        'www.facebook.com' => null,
        'www.amazon.com' => null
    ] : [
        'www.baidu.com' => null,
        'www.taobao.com' => null,
        'www.qq.com' => null,
        'www.swoole.com' => null
    ];

    $first_time = microtime(true);
    for ($n = MAX_CONCURRENCY; $n--;) {
        foreach ($map as $host => &$ip) {
            $ip = co::gethostbyname($host);
            Assert::assert(preg_match(IP_REGEX, $ip));
        }
    }
    unset($ip);
    $first_time = microtime(true) - $first_time;
    phpt_var_dump($map);

    $cache_time = microtime(true);
    for ($n = MAX_CONCURRENCY; $n--;) {
        foreach ($map as $host => $ip) {
            $_ip = co::gethostbyname($host);
            Assert::same($ip, $_ip);
        }
    }
    $cache_time = microtime(true) - $cache_time;

    $no_cache_time = microtime(true);
    for ($n = MAX_CONCURRENCY; $n--;) {
        swoole_clear_dns_cache();
        $ip = co::gethostbyname(array_rand($map));
        Assert::assert(preg_match(IP_REGEX, $ip));
    }
    $no_cache_time = microtime(true) - $no_cache_time;

    $chan = new Chan(MAX_CONCURRENCY_MID);
    $no_cache_multi_time = microtime(true);
    for ($c = MAX_CONCURRENCY; $c--;) {
        go(function () use ($map, $chan) {
            swoole_clear_dns_cache();
            $ip = co::gethostbyname(array_rand($map));
            $chan->push(Assert::assert(preg_match(IP_REGEX, $ip)));
        });
    }
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        $chan->pop();
    }
    $no_cache_multi_time = microtime(true) - $no_cache_multi_time;

    phpt_var_dump($first_time, $cache_time, $no_cache_time, $no_cache_multi_time);
    Assert::assert($cache_time < 0.01);
    Assert::assert($cache_time < $first_time);
    Assert::assert($cache_time < $no_cache_time);
    Assert::assert($cache_time < $no_cache_multi_time);
    Assert::assert($no_cache_multi_time < $no_cache_time);
});
Swoole\Event::wait();
?>
--EXPECTF--
