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

// Send the HTTP headers first so the multipart header block can be read without fragmentation.
function send_split_request(ProcessManager $pm, string $boundary, string $body): string
{
    $request = build_request($boundary, $body);
    $headerLength = strpos($request, "\r\n\r\n") + 4;
    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    fwrite($socket, substr($request, 0, $headerLength));
    usleep(10000);
    fwrite($socket, substr($request, $headerLength));
    $response = stream_get_contents($socket);
    fclose($socket);

    return $response;
}

$probes = [
    tempnam(sys_get_temp_dir(), 'swoole-upload-probe-'),
    tempnam(sys_get_temp_dir(), 'swoole-upload-probe-'),
];
$handlerMarker = tempnam(sys_get_temp_dir(), 'swoole-upload-handler-');
$logFile = tempnam(sys_get_temp_dir(), 'swoole-upload-log-');
$uploadDir = sys_get_temp_dir() . '/swoole-upload-' . getmypid();
file_put_contents($probes[0], 'probe');
file_put_contents($probes[1], 'probe');
unlink($handlerMarker);
unlink($logFile);
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
$beforeFileBody = implode("\r\n", [
    '--' . $boundary,
    'Content-Disposition: form-data; name="field"',
    'Swoole-Upload-File: ' . $probes[0],
    '',
    'value',
    '--' . $boundary,
    'Content-Disposition: form-data; name="file"; filename="test.txt"',
    'Content-Type: text/plain',
    '',
    str_repeat('C', 80 * 1024),
    '--' . $boundary . '--',
    '',
]);
$fileBody = implode("\r\n", [
    '--' . $boundary,
    'Content-Disposition: form-data; name="file"; filename="test.txt"',
    'Content-Type: text/plain',
    '',
    str_repeat('D', 80 * 1024),
    '--' . $boundary . '--',
    '',
]);
$tooLargeBody = '';
// Keep the client body below the package limit; generated file markers make the rebuilt body exceed it.
for ($i = 0; $i < 455; $i++) {
    $tooLargeBody .= implode("\r\n", [
        '--' . $boundary,
        'Content-Disposition: form-data; name="file' . $i . '"; filename="test.txt"',
        'Content-Type: text/plain',
        '',
        'x',
    ]) . "\r\n";
}
$tooLargeBody .= '--' . $boundary . "--\r\n";
$malformedRequest = implode("\r\n", [
    'POST / HTTP/1.1',
    'Host: 127.0.0.1',
    'Connection: close',
    'Content-Type: multipart/form-data',
    'Content-Length: ' . (80 * 1024),
    '',
    str_repeat('x', 80 * 1024),
]);
$getRequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

$pm = new ProcessManager;
$pm->parentFunc = function () use (
    $pm,
    $boundary,
    $earlyBody,
    $lateBody,
    $beforeFileBody,
    $fileBody,
    $tooLargeBody,
    $malformedRequest,
    $getRequest,
    $probes,
    $handlerMarker,
    $uploadDir,
    $logFile
) {
    $response = send_request($pm, $malformedRequest);
    Assert::contains($response, '400 Bad Request');
    $response = send_request($pm, $getRequest);
    Assert::contains($response, 'UNEXPECTED');

    $response = send_request($pm, build_request($boundary, $earlyBody));
    Assert::contains($response, '400 Bad Request');
    Assert::same(glob($uploadDir . '/swoole.upfile.*'), []);

    $response = send_request($pm, build_request($boundary, $lateBody));
    Assert::contains($response, '400 Bad Request');
    Assert::same(glob($uploadDir . '/swoole.upfile.*'), []);

    $response = send_request($pm, build_request($boundary, $beforeFileBody));
    Assert::contains($response, '400 Bad Request');
    Assert::same(glob($uploadDir . '/swoole.upfile.*'), []);

    $response = send_split_request($pm, $boundary, $tooLargeBody);
    Assert::contains($response, '413 Request Entity Too Large');
    Assert::same(glob($uploadDir . '/swoole.upfile.*'), []);
    $log = file_get_contents($logFile);
    Assert::same(preg_match(
        '/Request Entity Too Large: header-length \(\d+\) \+ content-length \((\d+)\)/',
        $log,
        $match
    ), 1);
    Assert::greaterThan((int) $match[1], strlen($tooLargeBody));

    Assert::true(rmdir($uploadDir));
    $response = send_request($pm, build_request($boundary, $fileBody));
    Assert::contains($response, '503 Service Unavailable');

    Assert::false(file_exists($handlerMarker));
    Assert::true(file_exists($probes[0]));
    Assert::true(file_exists($probes[1]));
    Assert::contains($log, "reserved header 'Swoole-Upload-File'");

    unlink($probes[0]);
    unlink($probes[1]);
    unlink($logFile);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $probes, $handlerMarker, $uploadDir, $logFile) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => $logFile,
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
