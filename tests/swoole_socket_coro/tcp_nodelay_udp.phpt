--TEST--
swoole_socket_coro: open_tcp_nodelay ignored for udp socket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$errors = [];
set_error_handler(function (int $errno, string $errstr) use (&$errors) {
    $errors[] = $errstr;
    return true;
});

$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
Assert::true($socket->setProtocol(['open_tcp_nodelay' => true]));

restore_error_handler();

Assert::eq($errors, []);
echo "DONE\n";
?>
--EXPECT--
DONE
