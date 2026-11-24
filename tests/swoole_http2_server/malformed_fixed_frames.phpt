--TEST--
swoole_http2_server: fixed-size frames with a wrong payload length close the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $frame = function (int $type, string $payload, int $flags = 0, int $stream = 0) {
        return substr(pack('N', strlen($payload)), 1) . chr($type) . chr($flags) . pack('N', $stream) . $payload;
    };
    $preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    $cases = [
        'settings 5 bytes' => $frame(4, str_repeat("\x00", 5)),
        'settings 7 bytes' => $frame(4, str_repeat("\x00", 7)),
        'window_update 1 byte' => $frame(8, "\x00"),
        'window_update 0 byte' => $frame(8, ''),
        'rst_stream 1 byte' => $frame(3, "\x00", 0, 1),
        'goaway 3 bytes' => $frame(7, "\x00\x00\x00"),
    ];
    foreach ($cases as $name => $data) {
        $fp = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 3);
        stream_set_timeout($fp, 2);
        fwrite($fp, $preface . $frame(4, '') . $data);
        $closed = false;
        $deadline = microtime(true) + 2;
        while (microtime(true) < $deadline) {
            $r = fread($fp, 8192);
            if ($r === '' && feof($fp)) {
                $closed = true;
                break;
            }
        }
        echo $name, ': ', $closed ? 'closed' : 'open', "\n";
        fclose($fp);
    }
    // The server must still serve a well-formed frame after the malformed ones.
    $fp = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 3);
    fwrite($fp, $preface . $frame(4, '') . $frame(8, pack('N', 1)));
    usleep(200000);
    var_dump(!feof($fp));
    fclose($fp);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['open_http2_protocol' => true, 'log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function (Request $req, Response $resp) { $resp->end('ok'); });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
settings 5 bytes: closed
settings 7 bytes: closed
window_update 1 byte: closed
window_update 0 byte: closed
rst_stream 1 byte: closed
goaway 3 bytes: closed
bool(true)
