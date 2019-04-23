--TEST--
swoole_socket_coro: new socket failed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
if ($argv[1] ?? '' === 'ulimit') {
    try {
        for ($n = MAX_CONCURRENCY + 1; $n--;) {
            $sockets[] = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        }
        echo 'never here' . PHP_EOL;
    } catch (Co\Socket\Exception $e) {
        Assert::assert($e->getCode() === SOCKET_EMFILE);
        echo "DONE\n";
    }
} else {
    $n = MAX_CONCURRENCY;
    $_SERVER['TEST_PHP_EXECUTABLE'] = $_SERVER['TEST_PHP_EXECUTABLE'] ?? 'php';
    $dir = __DIR__;
    file_put_contents(
        '/tmp/ulimit.sh',
        "ulimit -n {$n} && {$_SERVER['TEST_PHP_EXECUTABLE']} {$_SERVER['PHP_SELF']} ulimit"
    );
    echo shell_exec('/bin/sh /tmp/ulimit.sh');
    @unlink('/tmp/ulimit.sh');
}
?>
--EXPECTF--
DONE
