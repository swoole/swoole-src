--TEST--
swoole_process/coro: ipc with coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;

const N = MAX_REQUESTS_LOW;

$proc1 = new Process(function (Process $proc) {
    $socket = $proc->exportSocket();
    $socket->setProtocol([
        'open_length_check' => true,
        'package_length_type' => 'n',
        'package_length_offset' => 0,
        'package_body_offset' => 2,
    ]);

    while ($data = $socket->recvPacket()) {
        if (strlen($data) == 2) {
            echo "END\n";
            return;
        }
        Assert::lengthBetween($data, 1024, 61000);
    }
    echo "ERROR\n";
}, false, 1, true);

Assert::assert($proc1->start());

$n = N;
while ($n--) {
    $len = rand(1024, 60000);
    $pkg = pack('n', $len) . random_bytes($len);
    $proc1->write($pkg);
}
$proc1->write(pack('n', 0));
swoole_process::wait(true);
?>
--EXPECT--
END
