--TEST--
swoole_runtime/stream_select: Bug #64438 proc_open hangs with stdin/out with 4097+ bytes
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    error_reporting(E_ALL);

    if (substr(PHP_OS, 0, 3) == 'WIN') {
        $cmd = PHP_BINARY . ' -n -r "fwrite(STDOUT, $in = file_get_contents(\'php://stdin\')); fwrite(STDERR, $in);"';
    } else {
        $cmd = PHP_BINARY . ' -n -r \'fwrite(STDOUT, $in = file_get_contents("php://stdin")); fwrite(STDERR, $in);\'';
    }
    $descriptors = [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']];
    $stdin = str_repeat('*', 4097);

    $options = array_merge(['suppress_errors' => true, 'bypass_shell' => false]);
    $process = proc_open($cmd, $descriptors, $pipes, getcwd(), [], $options);

    foreach ($pipes as $pipe) {
        stream_set_blocking($pipe, false);
    }
    $writePipes = [$pipes[0]];
    $stdinLen = strlen($stdin);
    $stdinOffset = 0;

    unset($pipes[0]);

    while ($pipes || $writePipes) {
        $r = $pipes;
        $w = $writePipes;
        $e = null;
        $n = stream_select($r, $w, $e, 60);

        if (false === $n) {
            break;
        } elseif ($n === 0) {
            proc_terminate($process);

        }
        if ($w) {
            $written = fwrite($writePipes[0], substr($stdin, $stdinOffset), 8192);
            if (false !== $written) {
                $stdinOffset += $written;
            }
            if ($stdinOffset >= $stdinLen) {
                fclose($writePipes[0]);
                $writePipes = null;
            }
        }

        foreach ($r as $pipe) {
            $type = array_search($pipe, $pipes);
            $data = fread($pipe, 8192);
            var_dump($data);
            if (false === $data || feof($pipe)) {
                fclose($pipe);
                unset($pipes[$type]);
            }
        }
    }
});
Swoole\Event::wait();
?>
--EXPECTF--
string(4097) "%s"
string(4097) "%s"
string(0) ""
string(0) ""
