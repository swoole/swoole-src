--TEST--
swoole_http_server: reject upload reserved header during preprocessing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;

function build_request(string $boundary, string $body): string
{
    return implode("\r\n", [
        'POST / HTTP/1.1',
        'Host: 127.0.0.1',
        'Connection: close',
        'Content-Type: multipart/form-data; boundary=' . $boundary,
        'Content-Length: ' . strlen($body),
        '',
        $body,
    ]);
}

function send_request(ProcessManager $pm, string $request): string
{
    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    @fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);

    return $response;
}

$probes = [
    tempnam(sys_get_temp_dir(), 'swoole-upload-probe-'),
    tempnam(sys_get_temp_dir(), 'swoole-upload-probe-'),
];
$handlerMarker = tempnam(sys_get_temp_dir(), 'swoole-upload-handler-');
$uploadDir = sys_get_temp_dir() . '/swoole-upload-' . getmypid();
file_put_contents($probes[0], 'probe');
file_put_contents($probes[1], 'probe');
unlink($handlerMarker);
mkdir_if_not_exists($uploadDir);

$boundary = '------------------------d3f990cdce762596';
$earlyBody = implode("\r\n", [
    '--' . $boundary,
    'Content-Disposition: form-data; name="file"; filename="test.txt"',
    'Swoole-Upload-File: ' . $probes[0],
    'Content-Type: text/plain',
    '',
    str_repeat('A', 80 * 1024),
    '--' . $boundary . '--',
    '',
]);
$lateBody = implode("\r\n", [
    '--' . $boundary,
    'Content-Disposition: form-data; name="file"; filename="test.txt"',
    'Content-Type: text/plain',
    '',
    str_repeat('B', 80 * 1024),
    '--' . $boundary,
    'Content-Disposition: form-data; name="field"',
    'Swoole-Upload-File: ' . $probes[1],
    '',
    'value',
    '--' . $boundary . '--',
    '',
]);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $boundary, $earlyBody, $lateBody, $probes, $handlerMarker, $uploadDir) {
    $response = send_request($pm, build_request($boundary, $earlyBody));
    Assert::contains($response, '400 Bad Request');

    $response = send_request($pm, build_request($boundary, $lateBody));
    Assert::contains($response, '400 Bad Request');
    Assert::false(file_exists($handlerMarker));
    Assert::true(file_exists($probes[0]));
    Assert::true(file_exists($probes[1]));

    foreach (glob($uploadDir . '/swoole.upfile.*') as $file) {
        unlink($file);
    }
    rmdir($uploadDir);
    unlink($probes[0]);
    unlink($probes[1]);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $probes, $handlerMarker, $uploadDir) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
        'package_max_length' => 64 * 1024,
        'upload_max_filesize' => 1024 * 1024,
        'upload_tmp_dir' => $uploadDir,
    ]);
    $http->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function (Request $request, Response $response) use ($probes, $handlerMarker) {
        foreach ($probes as $probe) {
            if (is_uploaded_file($probe)) {
                file_put_contents($handlerMarker, 'uploaded');
                break;
            }
        }
        $response->end('UNEXPECTED');
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
