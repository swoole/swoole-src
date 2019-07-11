<?php
file_put_contents(__DIR__ . '/tmp', '');

const C = 1000;
const N = 1000;

function dns_test()
{
    $res = co::gethostbyname('www.baidu.com');
    assert(!empty($res));
    if (empty($res)) {
        var_dump(swoole_last_error(), swoole_strerror(swoole_last_error(), 2));
    }
}

$s = microtime(true);
$c = N;
while ($c--) {
    go(function () use ($c) {
        $n = N;
        while ($n--) {
            $rand = rand(1, 999999999);
            if ($rand % 3 == 1) {
                $res = co::statvfs('/');
                assert(!empty($res));
            } elseif ($rand % 3 == 2) {
                assert(!empty(co::readFile(__FILE__)));
            } elseif ($rand % 3 == 0) {
                assert(!empty(co::writeFile(__DIR__ . '/tmp', "write-[$c, $n]\n", FILE_APPEND)));
            }
        }
    });
}
swoole_event_wait();
echo 'use ' . (microtime(true) - $s) . ' s' . PHP_EOL;

