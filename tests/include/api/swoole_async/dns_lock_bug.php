<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


function parallel_dns_lookup_without_cache($parallelCount, $host = null)
{
    swoole_async_set([
        "thread_num"        => 2,
        'disable_dns_cache' => true,
        'dns_lookup_random' => true,
    ]);


    for ($i = 0; $i < $parallelCount; $i++) {
        $randStr = RandStr::gen(20);

        if ($host === null) {
            $host = "www.{$i}$randStr.com";
        }

        swoole_async_dns_lookup($host, function($host, $ip) use($i) {
            echo "FIN:[i=$i, ip=$ip]\n";
        });
        echo $i, "\n";
    }
}

// TODO 管道会被塞满,之后发生拥堵
parallel_dns_lookup_without_cache(20000);
parallel_dns_lookup_without_cache(20000, "www.youzan.com");