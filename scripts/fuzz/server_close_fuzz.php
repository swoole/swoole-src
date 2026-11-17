<?php
/**
 * Randomized close/timing fuzzer for Swoole\WebSocket\Server (HTTP + WebSocket + length-protocol TCP).
 *
 * Usage: php -d extension=modules/swoole.so scripts/fuzz/server_close_fuzz.php [seconds=30] [seed=random] [mode=process|base]
 *
 * The server handlers randomly close/send/push/sendfile/pause at arbitrary times, while the clients send valid,
 * truncated, mutated and fragmented payloads and drop connections in several ways (FIN, RST, half-close,
 * mid-request). The run fails when the master dies abnormally, the server stops answering, or the server log
 * contains a crash marker. Re-run with the printed seed to replay the client side of a failure.
 */

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use Swoole\Process;
use Swoole\WebSocket\Server;

use function Swoole\Coroutine\run;

$duration = (int) ($argv[1] ?? 30);
$seed = isset($argv[2]) && $argv[2] !== 'random' ? (int) $argv[2] : random_int(1, PHP_INT_MAX >> 1);
$mode = ($argv[3] ?? 'process') === 'base' ? SWOOLE_BASE : SWOOLE_PROCESS;
$workdir = sys_get_temp_dir() . '/swoole_close_fuzz_' . getmypid();
@mkdir($workdir);
$logfile = "$workdir/server.log";
$bigfile = "$workdir/big.bin";
file_put_contents($bigfile, random_bytes(1 << 20));
$http_port = 19600 + getmypid() % 200;
$tcp_port = $http_port + 200;

echo "seed=$seed duration={$duration}s mode=", $mode === SWOOLE_BASE ? 'base' : 'process',
    " ports=$http_port,$tcp_port log=$logfile\n";

function pick(array $items)
{
    return $items[mt_rand(0, count($items) - 1)];
}

function pick_close_code(): int
{
    return pick([1000, 1001, 1002, 1003, 1007, 1008, 1009, 1011, 4000]);
}

function server_main(int $http_port, int $tcp_port, int $mode, string $logfile, string $bigfile): void
{
    $server = new Server('127.0.0.1', $http_port, $mode);
    $server->set([
        'worker_num' => 2,
        'log_file' => $logfile,
        'log_level' => SWOOLE_LOG_WARNING,
        'open_websocket_close_frame' => true,
        'heartbeat_idle_time' => 6,
        'heartbeat_check_interval' => 2,
        'buffer_output_size' => 256 * 1024,
        'socket_buffer_size' => 64 * 1024,
        'send_yield' => true,
        'enable_coroutine' => true,
    ]);

    $tcp = $server->listen('127.0.0.1', $tcp_port, SWOOLE_SOCK_TCP);
    $tcp->set([
        'open_length_check' => true,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'package_max_length' => 1 << 20,
        'open_http_protocol' => false,
        'open_websocket_protocol' => false,
    ]);

    $chaos = function (Server $server, int $fd, string $payload) use ($bigfile) {
        switch (mt_rand(0, 9)) {
        case 0:
            $server->close($fd);
            break;
        case 1:
            $server->close($fd, true);
            break;
        case 2:
            $server->send($fd, $payload);
            $server->close($fd);
            break;
        case 3:
            $server->sendfile($fd, $bigfile);
            break;
        case 4:
            Coroutine::sleep(mt_rand(1, 3 + 1) / 1000);
            $server->send($fd, str_repeat('x', mt_rand(1, 300000)));
            break;
        case 5:
            Coroutine::sleep(mt_rand(1, 5 + 1) / 1000);
            $server->close($fd);
            break;
        case 6:
            $server->pause($fd);
            Coroutine::sleep(mt_rand(1, 5 + 1) / 1000);
            $server->resume($fd);
            break;
        case 7:
            if ($server->exist($fd)) {
                $server->getClientInfo($fd);
            }
            break;
        default:
            $server->send($fd, $payload);
        }
    };

    $server->on('request', function ($req, $resp) use ($server, $chaos, $bigfile) {
        $fd = $req->fd;
        switch (mt_rand(0, 8)) {
        case 0:
            $chaos($server, $fd, 'x');
            break;
        case 1:
            $resp->sendfile($bigfile);
            break;
        case 2:
            $resp->write(str_repeat('a', mt_rand(1, 100000)));
            Coroutine::sleep(mt_rand(1, 4 + 1) / 1000);
            $resp->write('b');
            $resp->end();
            break;
        case 3:
            $resp->detach();
            Coroutine::sleep(mt_rand(1, 4 + 1) / 1000);
            $resp->close();
            break;
        case 4:
            $resp->status(404);
            $resp->end($req->rawContent());
            break;
        case 5:
            $resp->header('X-Fuzz', 'ok');
            $resp->cookie('a', str_repeat('b', mt_rand(1, 200)));
            $resp->end(json_encode($req->get ?? []));
            break;
        case 6:
            Coroutine::sleep(mt_rand(1, 8 + 1) / 1000);
            $resp->end('late');
            break;
        case 7:
            $resp->upgrade();
            break;
        default:
            $resp->end('ok');
        }
    });

    $server->on('open', function (Server $server, $req) use ($chaos) {
        if (mt_rand(0, 6) === 0) {
            $chaos($server, $req->fd, 'open');
        }
    });

    $server->on('message', function (Server $server, $frame) use ($chaos) {
        switch (mt_rand(0, 6)) {
        case 0:
            $server->disconnect($frame->fd, pick_close_code(), 'bye');
            break;
        case 1:
            $server->push($frame->fd, str_repeat('p', mt_rand(1, 200000)));
            break;
        case 2:
            $chaos($server, $frame->fd, 'm');
            break;
        case 3:
            $server->push($frame->fd, $frame->data, mt_rand(0, 1) ? WEBSOCKET_OPCODE_BINARY : WEBSOCKET_OPCODE_TEXT);
            $server->close($frame->fd);
            break;
        default:
            $server->push($frame->fd, $frame->data);
        }
    });

    $server->on('close', function (Server $server, int $fd) {
        // Touching the closed fd must be safe.
        $server->exist($fd);
        $server->getClientInfo($fd);
        $server->send($fd, 'after-close');
    });

    $tcp->on('receive', function (Server $server, int $fd, int $rid, string $data) use ($chaos) {
        $chaos($server, $fd, pack('N', 4) . 'pong');
    });

    $server->on('workerStart', function (Server $server, int $wid) {
        mt_srand(crc32("worker$wid") ^ (int) (microtime(true) * 1000));
        // Server-side random closes of live connections, racing with client activity.
        Swoole\Timer::tick(mt_rand(5, 20), function () use ($server) {
            foreach ($server->connections as $fd) {
                if (mt_rand(0, 40) === 0) {
                    $server->close($fd, (bool) mt_rand(0, 1));
                }
            }
        });
    });

    $server->start();
}

function ws_frame(int $opcode, string $payload, bool $mask = true, bool $fin = true): string
{
    $len = strlen($payload);
    $b = chr(($fin ? 0x80 : 0) | $opcode);
    $m = $mask ? 0x80 : 0;
    if ($len < 126) {
        $b .= chr($m | $len);
    } elseif ($len < 65536) {
        $b .= chr($m | 126) . pack('n', $len);
    } else {
        $b .= chr($m | 127) . pack('J', $len);
    }
    if ($mask) {
        $key = random_bytes(4);
        $b .= $key;
        for ($i = 0; $i < $len; $i++) {
            $payload[$i] = $payload[$i] ^ $key[$i % 4];
        }
    }
    return $b . $payload;
}

function mutate(string $s): string
{
    $n = strlen($s);
    if ($n === 0) {
        return random_bytes(mt_rand(1, 16));
    }
    switch (mt_rand(0, 5)) {
    case 0:
        for ($i = mt_rand(1, 4); $i > 0; $i--) {
            $s[mt_rand(0, $n - 1)] = chr(mt_rand(0, 255));
        }
        return $s;
    case 1:
        return substr($s, 0, mt_rand(0, $n - 1));
    case 2:
        $a = mt_rand(0, $n - 1);
        return substr($s, 0, $a) . substr($s, $a, mt_rand(1, 32)) . substr($s, $a);
    case 3:
        $a = mt_rand(0, $n - 1);
        return substr($s, 0, $a) . pick(["\x00", "\xff\xff\xff\xff", "\r\n\r\n", "\r\n", '%', '\\']) . substr($s, $a);
    case 4:
        return $s . random_bytes(mt_rand(1, 64));
    default:
        return $s;
    }
}

function http_payload(string $path): string
{
    $body = random_bytes(mt_rand(0, 2000));
    switch (mt_rand(0, 7)) {
    case 0:
        return "GET $path?a=1&b[]=2&c=%zz HTTP/1.1\r\nHost: x\r\nCookie: a=b; c=%41\r\n\r\n";
    case 1:
        return "POST $path HTTP/1.1\r\nHost: x\r\nContent-Length: " . strlen($body) . "\r\n\r\n$body";
    case 2:
        return "POST $path HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            . dechex(strlen($body)) . "\r\n$body\r\n0\r\n\r\n";
    case 3:
        $boundary = 'fuzz' . mt_rand();
        $m = "--$boundary\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n$body\r\n--$boundary--\r\n";
        return "POST $path HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=$boundary\r\n"
            . 'Content-Length: ' . strlen($m) . "\r\n\r\n$m";
    case 4:
        return "GET $path HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\nGET $path HTTP/1.1\r\nHost: x\r\n\r\n";
    case 5:
        return "GET $path HTTP/1.1\r\nHost: x\r\nRange: bytes=0-10,20-30\r\nAccept-Encoding: gzip, br\r\n\r\n";
    case 6:
        return "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . random_bytes(mt_rand(0, 64));
    default:
        return "POST $path HTTP/1.1\r\nHost: x\r\nContent-Length: " . mt_rand(0, 5000) . "\r\n\r\n" . $body;
    }
}

function ws_handshake(): string
{
    return "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        . 'Sec-WebSocket-Key: ' . base64_encode(random_bytes(16)) . "\r\nSec-WebSocket-Version: 13\r\n\r\n";
}

function ws_payload(): string
{
    $frames = '';
    for ($i = mt_rand(1, 4); $i > 0; $i--) {
        switch (mt_rand(0, 6)) {
        case 0:
            $frames .= ws_frame(WEBSOCKET_OPCODE_TEXT, random_bytes(mt_rand(0, 300)));
            break;
        case 1:
            $frames .= ws_frame(WEBSOCKET_OPCODE_BINARY, random_bytes(mt_rand(0, 70000)));
            break;
        case 2:
            $frames .= ws_frame(WEBSOCKET_OPCODE_PING, random_bytes(mt_rand(0, 125)));
            break;
        case 3:
            $frames .= ws_frame(WEBSOCKET_OPCODE_CLOSE, pack('n', pick_close_code()) . 'x');
            break;
        case 4:
            $frames .= ws_frame(WEBSOCKET_OPCODE_TEXT, random_bytes(mt_rand(1, 50)), true, false)
                . ws_frame(0, random_bytes(mt_rand(1, 50)), true, true);
            break;
        case 5:
            $frames .= ws_frame(WEBSOCKET_OPCODE_TEXT, 'unmasked', false);
            break;
        default:
            $frames .= mutate(ws_frame(WEBSOCKET_OPCODE_TEXT, random_bytes(mt_rand(0, 100))));
        }
    }
    return $frames;
}

function tcp_payload(): string
{
    $body = random_bytes(mt_rand(0, 3000));
    switch (mt_rand(0, 4)) {
    case 0:
        return pack('N', strlen($body)) . $body;
    case 1:
        return pack('N', strlen($body) + 4) . $body;
    case 2:
        return pack('N', 0xffffffff) . $body;
    case 3:
        return pack('N', mt_rand(0, 1 << 21)) . $body;
    default:
        return mutate(pack('N', strlen($body)) . $body);
    }
}

function send_fragmented(Socket $sock, string $data): bool
{
    $offset = 0;
    $len = strlen($data);
    while ($offset < $len) {
        $n = mt_rand(1, 3) === 1 ? mt_rand(1, 8) : mt_rand(1, max(1, $len));
        $chunk = substr($data, $offset, $n);
        $offset += $n;
        if ($sock->send($chunk, 0.5) === false) {
            return false;
        }
        if (mt_rand(0, 5) === 0) {
            Coroutine::sleep(mt_rand(1, 3 + 1) / 1000);
        }
    }
    return true;
}

function finish(Socket $sock): void
{
    switch (mt_rand(0, 4)) {
    case 0:
        $sock->close();
        break;
    case 1:  // RST
        $sock->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 0]);
        $sock->close();
        break;
    case 2:  // half close, then wait for the peer
        $sock->shutdown(SHUT_WR);
        $sock->recv(65536, 0.05);
        $sock->close();
        break;
    case 3:  // read a bit, then drop
        $sock->recv(mt_rand(1, 4096), 0.02);
        $sock->close();
        break;
    default:
        Coroutine::sleep(mt_rand(1, 10 + 1) / 1000);
        $sock->close();
    }
}

function one_client(int $http_port, int $tcp_port, array &$stat): void
{
    $kind = mt_rand(0, 3);
    $sock = new Socket(AF_INET, SOCK_STREAM, 0);
    if (!$sock->connect('127.0.0.1', $kind === 3 ? $tcp_port : $http_port, 1)) {
        $stat['connect_fail']++;
        return;
    }
    $stat['connected']++;
    switch ($kind) {
    case 0:
        $payload = http_payload(pick(['/', '/a', '/x?y=1', '/../../etc/passwd', '/%00', '/' . str_repeat('a', mt_rand(1, 9000))]));
        if (mt_rand(0, 3) === 0) {
            $payload = mutate($payload);
        }
        break;
    case 1:
    case 2:
        send_fragmented($sock, ws_handshake());
        if (mt_rand(0, 4) !== 0) {
            $sock->recv(4096, 0.2);
        }
        $payload = ws_payload();
        break;
    default:
        $payload = tcp_payload();
    }
    if (send_fragmented($sock, $payload) && mt_rand(0, 2) === 0) {
        $sock->recv(mt_rand(1, 200000), mt_rand(0, 20) / 1000);
    }
    finish($sock);
}

// The server answers randomly, so a probe only needs an answer or an orderly close.
function healthy(int $port): bool
{
    $sock = new Socket(AF_INET, SOCK_STREAM, 0);
    if (!$sock->connect('127.0.0.1', $port, 2)) {
        return false;
    }
    $sock->send("GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    $data = $sock->recv(65536, 3);
    $ok = $data !== false;
    $sock->close();
    return $ok;
}

$server_process = new Process(function () use ($http_port, $tcp_port, $mode, $logfile, $bigfile) {
    server_main($http_port, $tcp_port, $mode, $logfile, $bigfile);
}, false, 0, false);
$server_process->start();
$server_pid = $server_process->pid;

$deadline = microtime(true) + 5;
while (microtime(true) < $deadline) {
    $c = @stream_socket_client("tcp://127.0.0.1:$http_port", $e, $es, 0.2);
    if ($c) {
        fclose($c);
        break;
    }
    usleep(50000);
}

mt_srand($seed);
$stat = ['connected' => 0, 'connect_fail' => 0, 'health_fail' => 0, 'exceptions' => 0];
$failed = false;

run(function () use ($duration, $http_port, $tcp_port, &$stat, $server_pid, &$failed) {
    $end = microtime(true) + $duration;
    $concurrency = 32;
    $running = 0;
    $last_health = microtime(true);
    while (microtime(true) < $end) {
        while ($running < $concurrency) {
            $running++;
            Coroutine::create(function () use (&$running, $http_port, $tcp_port, &$stat) {
                try {
                    one_client($http_port, $tcp_port, $stat);
                } catch (Throwable $e) {
                    $stat['exceptions']++;
                } finally {
                    $running--;
                }
            });
        }
        Coroutine::sleep(0.002);
        if (microtime(true) - $last_health > 2) {
            $last_health = microtime(true);
            if (!Process::kill($server_pid, 0)) {
                echo "FAIL: server master is gone\n";
                $failed = true;
                return;
            }
            if (!healthy($http_port)) {
                $stat['health_fail']++;
                echo "WARN: health probe failed\n";
            }
        }
    }
    while ($running > 0) {
        Coroutine::sleep(0.05);
    }
    for ($i = 0; $i < 5 && !healthy($http_port); $i++) {
        Coroutine::sleep(0.5);
    }
    if (!healthy($http_port)) {
        echo "FAIL: server does not answer after the run\n";
        $failed = true;
    }
});

if (Process::kill($server_pid, 0)) {
    Process::kill($server_pid, SIGTERM);
}
$deadline = microtime(true) + 10;
$status = null;
while (microtime(true) < $deadline) {
    $status = Process::wait(false);
    if ($status) {
        break;
    }
    usleep(100000);
}
if (!$status) {
    echo "FAIL: server did not exit on SIGTERM within 10s\n";
    Process::kill($server_pid, SIGKILL);
    $failed = true;
} elseif ($status['signal'] !== 0 && $status['signal'] !== SIGTERM) {
    echo "FAIL: server master killed by signal {$status['signal']}\n";
    $failed = true;
}

$log = @file_get_contents($logfile) ?: '';
foreach (['abnormal exit', 'Segmentation', 'SIGSEGV', 'Aborted', 'AddressSanitizer', 'Assertion', 'double free', 'corrupt'] as $marker) {
    if (stripos($log, $marker) !== false) {
        echo "FAIL: log contains '$marker'\n";
        $failed = true;
    }
}

echo 'stats: ', json_encode($stat), "\n";
echo "seed=$seed\n";
if ($failed) {
    echo "RESULT: FAIL (workdir kept: $workdir)\n";
    exit(1);
}
echo "RESULT: OK\n";
array_map('unlink', glob("$workdir/*"));
@rmdir($workdir);
