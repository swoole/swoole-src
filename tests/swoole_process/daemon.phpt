--TEST--
swoole_process: daemon
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const FILE = __DIR__ . '/output.txt';
use  Swoole\Process;

$process = new Process('python_process', true);
$pid = $process->start();

function python_process(swoole_process $worker)
{
    $fp = fopen(FILE, 'a');
    Process::daemon(1, 1, [null, $fp, $fp]);

    fwrite(STDOUT, "ERROR 1\n");
    fwrite(STDOUT, "ERROR 2\n");
    fwrite(STDOUT, "ERROR 3\n");

    fwrite(STDERR, "ERROR 4\n");
    fwrite(STDERR, "ERROR 5\n");
    fwrite(STDERR, "END\n");

}

Process::wait();

$fp = fopen(FILE, 'r');
for ($i = 0; $i < 100; $i++) {
    $line = fgets($fp);
    if (empty($line)) {
        usleep(100000);
    } else {
        echo $line;
        if ($line == "END\n") {
            break;
        }
    }
}
unlink(FILE);

?>
--EXPECT--
ERROR 1
ERROR 2
ERROR 3
ERROR 4
ERROR 5
END
