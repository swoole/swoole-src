--TEST--
swoole_runtime/stream_select: Bug #64770 stream_select() fails with pipes from proc_open()
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $descs = [
        0 => ['pipe', 'r'], // stdin
        1 => ['pipe', 'w'], // stdout
        2 => ['pipe', 'w'], // strerr
    ];

    $other_opts = ['suppress_errors' => false];

    $cmd = (substr(PHP_OS, 0, 3) == 'WIN') ? 'dir' : 'ls';
    $p = proc_open($cmd, $descs, $pipes, '.', null, $other_opts);

    if (is_resource($p)) {
        $data = '';

        while (1) {
            $w = $e = null;
            $n = stream_select($pipes, $w, $e, 300);

            if ($n === false) {
                echo "no streams \n";
                break;
            } else {
                if ($n === 0) {
                    echo "process timed out\n";
                    proc_terminate($p, 9);
                    break;
                } else {
                    if ($n > 0) {
                        $line = fread($pipes[1], 8192);
                        if (strlen($line) == 0) {
                            /* EOF */
                            break;
                        }
                        $data .= $line;
                    }
                }
            }
        }
        var_dump(strlen($data));

        $ret = proc_close($p);
        var_dump($ret);
    } else {
        echo "no process\n";
    }
});
Swoole\Event::wait();
?>
--EXPECTF--
int(%d)
int(0)
