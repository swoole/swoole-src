<?php
// Resolve a hostname without blocking the event loop ('localhost' needs no
// external network). Run: php examples/coroutine/system_dns_lookup.php
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    echo 'dnsLookup: ', print_r(System::dnsLookup('localhost'), true), PHP_EOL;
    echo 'gethostbyname: ', System::gethostbyname('localhost'), PHP_EOL;
});
