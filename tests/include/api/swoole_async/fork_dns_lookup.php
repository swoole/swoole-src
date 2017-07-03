<?php


require_once __DIR__ . "/../../../include/bootstrap.php";

fork_dns_lookup(null);

fork_dns_lookup("www.youzan.com");

function fork_dns_lookup($host = null, $c = 10, $n = 100)
{
    swoole_async_set([
        "thread_num"        => 2,
        'disable_dns_cache' => true,
        'dns_lookup_random' => true,
    ]);


    for ($i = 0; $i < $c; $i++) {
        $pid = pcntl_fork();

        if ($pid < 0) {
            exit("fork fail");
        }

        if ($pid === 0) {
            $pid = posix_getpid();
            for ($j = 0; $j < $n; $j++) {
                if ($host === null) {
                    $randStr = RandStr::gen(15);
                    $host = "www.i{$i}j{$j}pid{$pid}000$randStr.com";
                }

                echo "$host start\n";
                swoole_async_dns_lookup($host, function($host, $ip) use($i, $j, $pid) {
                    echo "FIN: i{$i} j{$j} pid{$pid} -> $ip\n";
                });
            }
            exit;
        }
    }

    while (pcntl_wait($status));
}