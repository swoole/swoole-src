--TEST--
swoole_http2_server: static responses wait for both windows without blocking frame parsing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

$file = tempnam(sys_get_temp_dir(), 'swoole-http2-flow-');
rename($file, $file . '.txt');
$file .= '.txt';
file_put_contents($file, str_repeat('F', 200000));
$directory = $file . '.dir';
mkdir($directory);
try {
    foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $file, $directory) {
            try {
                $peer = new Http2FlowPeer($pm->getFreePort(), 0);
                $peer->request(1, '/' . basename($file));
                $peer->barrier();
                Assert::same($peer->total, 0);
                $peer->update(1, 200000);
                $peer->bytes(1, 65535);
                $peer->barrier();
                Assert::same($peer->total, 65535);
                $peer->update(0, 200000 - 65535);
                $peer->bytes(1, 200000);
                Assert::same($peer->bodies[1], file_get_contents($file));
                Assert::true(isset($peer->ended[1]));
                $peer->settings(65535);
                $peer->update(0, 8);
                $peer->request(3, '/' . basename($directory) . '/');
                $peer->bytes(3, 8);
                Assert::same($peer->bodies[3], 'fallback');
                $peer->close();
            } finally {
                $pm->kill();
            }
        };
        $pm->childFunc = function () use ($pm, $mode, $file) {
            http2_flow_server($pm, $mode, function ($request, $response) {
                Assert::true(str_ends_with($request->server['request_uri'], '.dir/'));
                $response->end('fallback');
            }, false, [
                'enable_static_handler' => true,
                'document_root' => dirname($file),
                'http_index_files' => ['missing.html'],
            ]);
        };
        $pm->childFirst();
        $pm->run();
    }
} finally {
    unlink($file);
    rmdir($directory);
}
echo "DONE\n";
?>
--EXPECT--
DONE
