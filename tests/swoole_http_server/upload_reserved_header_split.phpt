--TEST--
swoole_http_server: reserved upload header cannot be forged through header names split across reads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('requires Unix process support', PHP_OS_FAMILY === 'Windows');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
file_put_contents($probe, 'keep this file');

function send_split(int $port, string $probe, array $first_names, bool $forge): string
{
    $name = str_repeat('A', 24);
    $head = "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n" . "--b\r\nContent-Disposition: form-data; name=\"text\"\r\n" . $name . ':';
    $second = " $probe\r\n\r\n";
    // The forged header is placed where the already accepted name was stored in the reactor read buffer.
    $padding = strlen($head) - strlen($name) - 1 - strlen($second);
    $second .= str_repeat('x', $padding) . ($forge ? "A: b\r\nSwoole-Upload-File" : str_repeat('y', 24));
    $second .= "\r\n--b\r\nContent-Disposition: form-data; name=\"big\"; filename=\"b.bin\"\r\n\r\n" . str_repeat('z', 70000) . "\r\n--b--\r\n";
    $length = strlen($head) + strlen($second);
    $fp = stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 5);
    stream_set_timeout($fp, 5);
    $request = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        . "Content-Type: multipart/form-data; boundary=b\r\nContent-Length: $length\r\n\r\n";
    fwrite($fp, $request . $head);
    usleep(700000);
    @fwrite($fp, $second);
    $response = (string) @stream_get_contents($fp);
    fclose($fp);
    return $response;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $probe) {
    // Control: the same layout without the forged header is accepted.
    $ok = send_split($pm->getFreePort(), $probe, [], false);
    Assert::contains($ok, '"probe_uploaded":false');
    $bad = send_split($pm->getFreePort(), $probe, [], true);
    // The forged bytes must stay inert: the path is neither accepted as an upload nor deleted.
    Assert::notContains($bad, '"probe_uploaded":true');
    clearstatcache();
    Assert::same(file_get_contents($probe), 'keep this file');
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $probe) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'package_max_length' => 16384,
        'upload_max_filesize' => 262144,
    ]);
    $server->on('WorkerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function ($request, $response) use ($probe) {
        $response->end(json_encode(['probe_uploaded' => is_uploaded_file($probe), 'files' => $request->files]));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
clearstatcache();
Assert::same(file_get_contents($probe), 'keep this file');
unlink($probe);
echo "DONE\n";
?>
--EXPECT--
DONE
