--TEST--
swoole_http_server: untrusted upload paths survive request destruction and PHP shutdown
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('requires Unix process support', PHP_OS_FAMILY === 'Windows');
skip_if_function_not_exist('proc_open');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function run_upload_shutdown_php(string $code, array $arguments): array
{
    $command = 'exec ' . escapeshellarg(PHP_BINARY) . ' ' . getenv('TEST_PHP_EXTRA_ARGS')
        . ' -r ' . escapeshellarg($code) . ' -- ""';
    foreach ($arguments as $argument) {
        $command .= ' ' . escapeshellarg((string) $argument);
    }
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start PHP');
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = $stderr = '';
    $deadline = microtime(true) + 10;
    try {
        do {
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($process, 9);
                throw new RuntimeException('PHP shutdown timed out');
            }
            usleep(10000);
        } while (true);
        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
    } finally {
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);
    }
    return [$status['exitcode'] >= 0 ? $status['exitcode'] : $exit, $stdout, $stderr];
}

$probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
$manifest = tempnam(sys_get_temp_dir(), 'swoole-upload-manifest-');
file_put_contents($probe, 'keep this file');
$code = <<<'PHP'
$probe = $argv[2];
$manifest = $argv[3];
$guard = (int) $argv[4];
$retain = (int) $argv[5];
$body = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
    . "sWoOlE-uPlOaD-fIlE: $probe\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b--\r\n";
$request = Swoole\Http\Request::create();
$request->parse("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=b\r\n"
    . 'Content-Length: ' . strlen($body) . "\r\n\r\n$body");
$file = $request->files['file'];
if (!$request->isCompleted() || $file['error'] !== UPLOAD_ERR_OK
    || $file['tmp_name'] === $probe || is_uploaded_file($probe)
    || !is_uploaded_file($file['tmp_name']) || file_get_contents($file['tmp_name']) !== 'body') {
    throw new RuntimeException('Untrusted marker affected the upload');
}
file_put_contents($manifest, $file['tmp_name']);
if ($guard === 1) {
    $request->tmpfiles = [];
} elseif ($guard === 2) {
    $request->tmpfiles = null;
} elseif ($guard === 3) {
    $empty = [];
    $request->tmpfiles = &$empty;
}
if (!$retain) {
    unset($request);
}
if (file_get_contents($probe) !== 'keep this file' || is_uploaded_file($probe)) {
    throw new RuntimeException('Request cleanup touched the probe');
}
echo "OK\n";
PHP;

try {
    foreach ([0, 1, 2, 3] as $guard) {
        foreach ([0, 1] as $retain) {
            $result = run_upload_shutdown_php($code, [$probe, $manifest, $guard, $retain]);
            Assert::same($result, [0, "OK\n", '']);
            clearstatcache();
            Assert::same(file_get_contents($probe), 'keep this file');
            // Check after the child exits, beyond user shutdown callbacks and SAPI upload cleanup.
            Assert::false(file_exists(file_get_contents($manifest)));
        }
    }
    echo "DONE\n";
} finally {
    if (is_file($probe)) {
        unlink($probe);
    }
    unlink($manifest);
}
?>
--EXPECT--
DONE
