--TEST--
swoole_http_server_coro: upload reserved header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Process;
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
file_put_contents($probe, 'probe');
$content = 'direct upload body';
$boundary = '------------------------d3f990cdce762596';
$body = implode("\r\n", [
    '--' . $boundary,
    'Content-Disposition: form-data; name="file"; filename="test.txt"',
    'Swoole-Upload-File: ' . $probe,
    'Content-Type: text/plain',
    '',
    $content,
    '--' . $boundary . '--',
    '',
]);
$request = implode("\r\n", [
    'POST / HTTP/1.1',
    'Host: 127.0.0.1',
    'Connection: close',
    'Content-Type: multipart/form-data; boundary=' . $boundary,
    'Content-Length: ' . strlen($body),
    '',
    $body,
]);

$pm->parentFunc = function () use ($pm, $request, $probe, $content) {
    $sock = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    fwrite($sock, $request);
    stream_set_chunk_size($sock, 2 * 1024 * 1024);
    $response = fread($sock, 2 * 1024 * 1024);
    fclose($sock);
    [, $responseBody] = explode("\r\n\r\n", $response, 2);
    $json = json_decode($responseBody, true);
    Assert::true(is_array($json));
    Assert::true($json['has_file']);
    Assert::same($json['md5'], md5($content));
    Assert::false($json['tmp_name_is_probe']);
    Assert::false($json['probe_uploaded']);
    Assert::true(file_exists($probe));
    unlink($probe);
};

$pm->childFunc = function () use ($pm, $probe) {
    run(function () use ($pm, $probe) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) use ($server, $probe) {
            $file = $request->files['file'] ?? null;
            $tmpName = $file['tmp_name'] ?? '';
            $response->end(json_encode([
                'has_file' => is_array($file),
                'md5' => is_file($tmpName) ? md5_file($tmpName) : '',
                'tmp_name_is_probe' => $tmpName === $probe,
                'probe_uploaded' => is_uploaded_file($probe),
            ]));
            $server->shutdown();
        });
        Process::signal(SIGTERM, function () use ($server) {
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
