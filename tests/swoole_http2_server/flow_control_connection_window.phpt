--TEST--
swoole_http2_server: open the connection window when http2_init_window_size is larger
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

const BODY_SIZE = 100000;
// The connection window starts at 65535 whatever SETTINGS_INITIAL_WINDOW_SIZE says
const CONNECTION_WINDOW = 65535;

function send_data($client, int $length, bool $end): void
{
    while ($length > 0) {
        $n = min(16384, $length);
        $length -= $n;
        fwrite($client, http2_test_frame(0, $end && $length === 0 ? 1 : 0, 1, str_repeat('a', $n)));
    }
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $errstr, 2);
    stream_set_timeout($client, 2);
    $headers = "\x83\x86\x04\x01/\x01\x09localhost";
    fwrite($client, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_test_frame(4, 0, 0) . http2_test_frame(1, 4, 1, $headers));
    send_data($client, CONNECTION_WINDOW, false);

    $update = http2_test_wait_for_frame($client, 8);
    Assert::same($update['streamId'], 0);
    send_data($client, BODY_SIZE - CONNECTION_WINDOW, true);
    Assert::same(http2_test_wait_for_frame($client, 0)['payload'], (string) BODY_SIZE);
    fclose($client);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http2_init_window_size' => 1024 * 1024,
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        $response->end(strlen($request->rawContent()));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
