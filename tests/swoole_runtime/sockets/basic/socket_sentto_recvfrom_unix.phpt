--TEST--
swoole_runtime/sockets/basic: Test if socket_recvfrom() receives data sent by socket_sendto() through a Unix domain socket
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (substr(PHP_OS, 0, 3) == 'WIN') {
    die('skip.. Not valid for Windows');
}
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $socket = socket_create(AF_UNIX, SOCK_DGRAM, 0);
    if (!$socket) {
        die('Unable to create AF_UNIX socket');
    }
    if (!socket_set_nonblock($socket)) {
        die('Unable to set nonblocking mode for socket');
    }
    var_dump(socket_recvfrom($socket, $buf, 12, 0, $from, $port)); //false (EAGAIN, no warning)
    $address = sprintf("/tmp/%s.sock", uniqid());
    if (!socket_bind($socket, $address)) {
        die("Unable to bind to $address");
    }

    $msg = "Ping!";
    $len = strlen($msg);
    $bytes_sent = socket_sendto($socket, $msg, $len, 0, $address);
    if ($bytes_sent == -1) {
        die('An error occurred while sending to the socket');
    } else if ($bytes_sent != $len) {
        die($bytes_sent . ' bytes have been sent instead of the ' . $len . ' bytes expected');
    }

    $from = "";
    var_dump(socket_recvfrom($socket, $buf, 0, 0, $from));
    $bytes_received = socket_recvfrom($socket, $buf, 12, 0, $from);
    if ($bytes_received == -1) {
        die('An error occurred while receiving from the socket');
    } else if ($bytes_received != $len) {
        die($bytes_received . ' bytes have been received instead of the ' . $len . ' bytes expected');
    }
    echo "Received $buf";

    socket_close($socket);
});
?>
--EXPECTF--
bool(false)
bool(false)
Received Ping!
--CREDITS--
Falko Menge <mail at falko-menge dot de>
PHP Testfest Berlin 2009-05-09
