--TEST--
swoole_coroutine_system: getaddrinfo without a service
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    // No service given: it must not be passed to getaddrinfo(3) as an empty string, which musl rejects.
    $ip_list = Swoole\Coroutine\System::getaddrinfo('localhost', AF_INET);
    Assert::true(is_array($ip_list), 'getaddrinfo() failed: ' . swoole_strerror(swoole_last_error()));
    Assert::true(in_array('127.0.0.1', $ip_list, true));

    // A service given explicitly still works.
    $ip_list = Swoole\Coroutine\System::getaddrinfo('localhost', AF_INET, SOCK_STREAM, STREAM_IPPROTO_TCP, '80');
    Assert::true(is_array($ip_list), 'getaddrinfo() failed: ' . swoole_strerror(swoole_last_error()));
    Assert::true(in_array('127.0.0.1', $ip_list, true));
    echo "DONE\n";
});
?>
--EXPECT--
DONE
