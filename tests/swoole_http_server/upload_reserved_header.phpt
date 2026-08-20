--TEST--
swoole_http_server: upload reserved header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function build_multipart_request(string $boundary, string $body, ?string $probe = null): string
{
    $headers = [
        'POST / HTTP/1.1',
        'Host: 127.0.0.1',
        'Connection: close',
    ];
    if ($probe !== null) {
        $headers[] = 'X-Probe-File: ' . $probe;
    }
    $headers[] = 'Content-Type: multipart/form-data; boundary=' . $boundary;
    $headers[] = 'Content-Length: ' . strlen($body);
    $headers[] = '';
    $headers[] = $body;

    return implode("\r\n", $headers);
}

function build_file_body(string $boundary, string $content, ?string $probe = null): string
{
    $headers = [
        '--' . $boundary,
        'Content-Disposition: form-data; name="file"; filename="test.txt"',
    ];
    if ($probe !== null) {
        $headers[] = 'Swoole-Upload-File: ' . $probe;
    }
    $headers[] = 'Content-Type: text/plain';
    $headers[] = '';
    $headers[] = $content;
    $headers[] = '--' . $boundary . '--';
    $headers[] = '';

    return implode("\r\n", $headers);
}

function send_raw_request(ProcessManager $pm, string $request): array
{
    $sock = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    fwrite($sock, $request);
    stream_set_chunk_size($sock, 2 * 1024 * 1024);
    $response = fread($sock, 2 * 1024 * 1024);
    fclose($sock);

    return explode("\r\n\r\n", $response, 2);
}

function run_upload_reserved_header(int $mode): void
{
    $pm = new ProcessManager;

    $pm->parentFunc = function () use ($pm) {
        $probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
        file_put_contents($probe, 'probe');
        $boundary = '------------------------d3f990cdce762596';

        $content = 'direct upload body';
        $body = build_file_body($boundary, $content, $probe);
        [, $responseBody] = send_raw_request($pm, build_multipart_request($boundary, $body, $probe));
        $json = json_decode($responseBody, true);
        Assert::true(is_array($json));
        Assert::true($json['has_file']);
        Assert::same($json['md5'], md5($content));
        Assert::false($json['tmp_name_is_probe']);
        Assert::false($json['probe_uploaded']);
        Assert::true(file_exists($probe));
        unlink($probe);

        $content = str_repeat('A', 80 * 1024);
        $body = build_file_body($boundary, $content);
        [, $responseBody] = send_raw_request($pm, build_multipart_request($boundary, $body));
        $json = json_decode($responseBody, true);
        Assert::true(is_array($json));
        Assert::true($json['has_file']);
        Assert::same($json['md5'], md5($content));
        Assert::same($json['file_count'], 1);

        $pm->kill();
    };

    $pm->childFunc = function () use ($pm, $mode) {
        $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $http->set([
            'log_file' => '/dev/null',
            'worker_num' => 1,
            'package_max_length' => 64 * 1024,
            'upload_max_filesize' => 1024 * 1024,
        ]);
        $http->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
            $probe = $request->header['x-probe-file'] ?? '';
            $file = $request->files['file'] ?? null;
            $tmpName = $file['tmp_name'] ?? '';
            $response->end(json_encode([
                'has_file' => is_array($file),
                'md5' => is_file($tmpName) ? md5_file($tmpName) : '',
                'tmp_name_is_probe' => $tmpName === $probe,
                'probe_uploaded' => is_uploaded_file($probe),
                'file_count' => count($request->files ?? []),
            ]));
        });
        $http->start();
    };

    $pm->childFirst();
    $pm->run();
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    run_upload_reserved_header($mode);
}
?>
--EXPECT--
