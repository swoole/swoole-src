--TEST--
swoole_process: daemon
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use  Swoole\Process;

$sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

$process = new Process(function (swoole_process $worker) use ($sockets) {
    fclose($sockets[1]);
    Process::daemon(1, 1, [null, $sockets[0], $sockets[0]]);

    fwrite(STDOUT, "ERROR 1\n");
    fwrite(STDOUT, "ERROR 2\n");
    fwrite(STDOUT, "ERROR 3\n");

    fwrite(STDERR, "ERROR 4\n");
    fwrite(STDERR, "ERROR 5\n");
    fwrite(STDERR, "END\n");
}, true);
$pid = $process->start();

Process::wait();
fclose($sockets[0]);

while (true) {
    $fp = $sockets[1];
    $line = fgets($fp);
    if (empty($line)) {
        break;
    } else {
        echo $line;
        if ($line == "END\n") {
            break;
        }
    }
}

?>
--EXPECT--
ERROR 1
ERROR 2
ERROR 3
ERROR 4
ERROR 5
END
