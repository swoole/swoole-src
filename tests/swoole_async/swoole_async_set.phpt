--TEST--
swoole_async: swoole_async_set

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";


swoole_async_set([
    "aio_mode" => 1,
    "thread_num" => 1,
    "enable_signalfd" => true,
    "socket_buffer_size" => 0,
    "socket_dontwait" => true,
    "aio_max_buffer" => 0,
    "disable_dns_cache" => true,
    "dns_lookup_random" => true,
    "enable_reuse_port" => true,
]);


// 一个线程 进行dns查询, 结果有序
$r = [];

$tokens = array_fill(0, 10, 0);

for($i = 0; $i < 10; $i++) {
    swoole_async_dns_lookup("www.youtube.com", function($domain, $ip) use($i, &$r, &$tokens) {
        //echo $domain, $ip, "\n";
        array_pop($tokens);
        $r[] = $i;
        if (empty($tokens)) {
            foreach($r as $i => $_i) {
                assert($i === $_i);
            }
            echo "SUCCESS";
        }

    });
}




?>

--EXPECT--
SUCCESS
