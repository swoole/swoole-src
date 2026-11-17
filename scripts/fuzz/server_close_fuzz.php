<?php
/**
 * Randomized close/timing fuzzer for Swoole\WebSocket\Server (HTTP + WebSocket + length-protocol TCP).
 *
 * Usage: php -d extension=modules/swoole.so scripts/fuzz/server_close_fuzz.php [seconds=30] [seed=random] [mode=process|base|thread]
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

// In thread mode every worker thread re-executes this script, so rebuild the server from the environment.
if (class_exists(Swoole\Thread::class) && Swoole\Thread::getArguments() !== null) {
    $cfg = json_decode(getenv('SWOOLE_CLOSE_FUZZ'), true);
    server_main($cfg['http_port'], $cfg['tcp_port'], SWOOLE_THREAD, $cfg['logfile'], $cfg['bigfile'], $cfg['seed'], $cfg['pidfile']);
    return;
}

$duration = (int) ($argv[1] ?? 30);
$seed = isset($argv[2]) && $argv[2] !== 'random' ? (int) $argv[2] : random_int(1, PHP_INT_MAX >> 1);
$mode_name = $argv[3] ?? 'process';
$mode = ['base' => SWOOLE_BASE, 'thread' => SWOOLE_THREAD][$mode_name] ?? SWOOLE_PROCESS;
$workdir = sys_get_temp_dir() . '/swoole_close_fuzz_' . getmypid();
@mkdir($workdir);
$logfile = "$workdir/server.log";
$bigfile = "$workdir/big.bin";
$pidfile = "$workdir/worker.pids";
file_put_contents($bigfile, random_bytes(1 << 20));
$http_port = 19600 + getmypid() % 200;
$tcp_port = $http_port + 200;

echo "seed=$seed duration={$duration}s mode=", $mode_name,
    " ports=$http_port,$tcp_port log=$logfile\n";

function pick(array $items)
{
    return $items[mt_rand(0, count($items) - 1)];
}

function pick_close_code(): int
{
    return pick([1000, 1001, 1002, 1003, 1007, 1008, 1009, 1011, 4000]);
}

function server_main(int $http_port, int $tcp_port, int $mode, string $logfile, string $bigfile, int $seed, string $pidfile): void
{
    // Settings are derived from the seed so a failing configuration can be replayed.
    mt_srand($seed);
    $worker_num = mt_rand(1, 4);  // keep the process count small: the fuzzer must not exhaust the host
    $max_request = pick([0, 0, mt_rand(100, 2000)]);
    if (getenv('FUZZ_MAX_REQUEST') !== false) {
        $max_request = (int) getenv('FUZZ_MAX_REQUEST');  // force frequent worker restarts
    }
    $h2 = mt_rand(0, 1) === 1;  // HTTP/2 requires dispatch_mode 2 or 4
    $dispatch_mode = $h2 ? pick([2, 4]) : ($mode === SWOOLE_PROCESS ? pick([1, 2, 4]) : 1);
    $out_size = pick([4096, 64 * 1024, 256 * 1024]);
    $sock_buf = pick([4096, 16 * 1024, 64 * 1024, 256 * 1024]);
    $task_num = pick([0, 0, 1, 2]);
    // dispatch_mode 1/3 in process mode has no onConnect, so a delayed connection could never be confirmed
    $delay_receive = mt_rand(0, 3) === 0 && !($mode === SWOOLE_PROCESS && in_array($dispatch_mode, [1, 3], true));
    $ssl_port = $http_port + 400;
    $use_ssl = defined('SWOOLE_SSL');
    echo "settings: worker_num=$worker_num max_request=$max_request dispatch_mode=$dispatch_mode " .
        "http2=" . (int) $h2 . " buffer_output_size=$out_size socket_buffer_size=$sock_buf task_worker_num=$task_num delay_receive=" .
        (int) $delay_receive . "\n";

    $server = new Server('127.0.0.1', $http_port, $mode);
    $server->set([
        'worker_num' => $worker_num,
        'max_request' => $max_request,
        'dispatch_mode' => $dispatch_mode,
        'reload_async' => (bool) mt_rand(0, 1),
        'send_timeout' => mt_rand(1, 3),
        'task_worker_num' => $task_num,
        'enable_delay_receive' => $delay_receive,
        'open_http2_protocol' => $h2,
        'log_file' => $logfile,
        'log_level' => SWOOLE_LOG_WARNING,
        'open_websocket_close_frame' => true,
        'heartbeat_idle_time' => 6,
        'heartbeat_check_interval' => 2,
        'buffer_output_size' => $out_size,
        'socket_buffer_size' => $sock_buf,
        'send_yield' => in_array($dispatch_mode, [2, 4], true) && $mode === SWOOLE_PROCESS,
        'enable_coroutine' => true,
        'init_arguments' => function () {
            return [1];
        },
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

    $server->listen('127.0.0.1', $http_port + 800, SWOOLE_SOCK_TCP);  // health probe port, always confirmed

    if ($use_ssl) {
        $ssl = $server->listen('127.0.0.1', $ssl_port, SWOOLE_SOCK_TCP | SWOOLE_SSL);
        $ssl->set([
            'ssl_cert_file' => __DIR__ . '/../../examples/ssl/ssl.crt',
            'ssl_key_file' => __DIR__ . '/../../examples/ssl/ssl.key',
            'open_http_protocol' => true,
            'open_websocket_protocol' => true,
        ]);
    }

    $chaos = function (Server $server, int $fd, string $payload) use ($bigfile, $task_num, $worker_num) {
        switch (mt_rand(0, 12)) {
        case 10:
            if ($task_num > 0) {
                $server->task(['fd' => $fd, 'op' => mt_rand(0, 3)]);
            }
            break;
        case 11:
            $server->sendMessage(json_encode(['fd' => $fd, 'op' => mt_rand(0, 2)]), mt_rand(0, $worker_num - 1));
            break;
        case 12:
            $server->close($fd);
            $server->close($fd);
            break;
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

    $server->on('task', function (Server $server, int $task_id, int $src_worker_id, $data) {
        usleep(mt_rand(0, 3000));
        switch ($data['op']) {
        case 0:
            $server->close($data['fd'], (bool) mt_rand(0, 1));
            break;
        case 1:
            $server->send($data['fd'], 'from-task');
            break;
        case 2:
            $server->send($data['fd'], 'from-task');
            $server->close($data['fd']);
            break;
        default:
            $server->exist($data['fd']);
        }
        $server->finish('done');
    });
    $server->on('finish', function () {
    });
    $server->on('pipeMessage', function (Server $server, int $src_worker_id, $message) {
        $m = json_decode($message, true);
        if (!$m) {
            return;
        }
        if ($m['op'] === 0) {
            $server->close($m['fd']);
        } elseif ($m['op'] === 1) {
            $server->send($m['fd'], 'from-pipe');
        } else {
            $server->getClientInfo($m['fd']);
        }
    });
    if ($delay_receive) {
        $server->on('connect', function (Server $server, int $fd) use ($http_port) {
            $info = $server->getClientInfo($fd);
            if ($info && $info['server_port'] === $http_port + 800) {
                $server->confirm($fd);
                return;
            }
            switch (mt_rand(0, 4)) {
            case 0:
                $server->confirm($fd);
                break;
            case 1:
                Swoole\Timer::after(mt_rand(1, 20), function () use ($server, $fd) {
                    $server->confirm($fd);
                });
                break;
            case 2:
                Swoole\Timer::after(mt_rand(1, 20), function () use ($server, $fd) {
                    $server->close($fd);
                    $server->confirm($fd);
                });
                break;
            case 3:
                $server->close($fd);
                break;
            default:  // never confirmed; the client or the heartbeat has to end it
            }
        });
    }

    $server->on('workerStart', function (Server $server, int $wid) use ($pidfile) {
        file_put_contents($pidfile, getmypid() . "\n", FILE_APPEND);
        mt_srand(crc32("worker$wid") ^ (int) (microtime(true) * 1000));
        // Server-side random closes of live connections, racing with client activity.
        Swoole\Timer::tick(mt_rand(5, 20), function () use ($server) {
            if (mt_rand(0, 20) === 0) {
                $server->stats();
                $server->getClientList(0, 20);
            }
            foreach ($server->connections as $fd) {
                if (mt_rand(0, 40) === 0) {
                    $server->close($fd, (bool) mt_rand(0, 1));
                }
            }
        });
    });

    // A user timer keeps the reactor alive; without clearing it a reload_async worker only exits
    // after the forced-termination timeout and the server stalls meanwhile.
    $server->on('workerExit', function (Server $server, int $wid) {
        Swoole\Timer::clearAll();
    });

    $server->start();
}

// Resident memory (MB), process and thread count of the server and all its descendants.
function tree_usage(int $root): array
{
    $parent = [];
    foreach (glob('/proc/[0-9]*', GLOB_ONLYDIR) as $dir) {
        $stat = @file_get_contents("$dir/stat");
        if ($stat !== false && preg_match('/^(\d+) \(.*\) \S (\d+)/s', $stat, $m)) {
            $parent[(int) $m[1]] = (int) $m[2];
        }
    }
    $rss = $procs = $threads = 0;
    foreach ($parent as $pid => $ppid) {
        for ($p = $pid, $i = 0; $p > 1 && $i < 32; $p = $parent[$p] ?? 0, $i++) {
            if ($p === $root) {
                $statm = @file_get_contents("/proc/$pid/statm");
                $rss += $statm ? (int) explode(' ', $statm)[1] * 4 / 1024 : 0;
                $procs++;
                $threads += count(@scandir("/proc/$pid/task") ?: []) - 2;
                break;
            }
        }
    }
    return [(int) $rss, $procs, $threads];
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

// TLS clients: complete or abort the handshake at random points and drop the connection abruptly.
function ssl_client(int $port, array &$stat): void
{
    switch (mt_rand(0, 3)) {
    case 0:  // garbage instead of a ClientHello
        $sock = new Socket(AF_INET, SOCK_STREAM, 0);
        if (!$sock->connect('127.0.0.1', $port, 1)) {
            $stat['connect_fail']++;
            return;
        }
        $stat['connected']++;
        send_fragmented($sock, pick(["\x16\x03\x01\x00\x10", "\x16\x03\x03\xff\xff", '', "GET / HTTP/1.1\r\n\r\n"]) . random_bytes(mt_rand(0, 300)));
        finish($sock);
        return;
    case 1:  // connect and leave without a handshake
        $sock = new Socket(AF_INET, SOCK_STREAM, 0);
        if (!$sock->connect('127.0.0.1', $port, 1)) {
            $stat['connect_fail']++;
            return;
        }
        $stat['connected']++;
        finish($sock);
        return;
    }
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $cli->set(['ssl_verify_peer' => false, 'timeout' => 1]);
    if (!$cli->connect('127.0.0.1', $port, 1)) {
        $stat['connect_fail']++;
        return;
    }
    $stat['connected']++;
    if (mt_rand(0, 1)) {
        $cli->send(http_payload('/ssl'));
    } else {
        $cli->send(ws_handshake());
        $cli->recv(0.2);
        $cli->send(ws_payload());
    }
    if (mt_rand(0, 1)) {
        $cli->recv(0.02);
    }
    $cli->close();
}

function h2_frame(int $type, int $flags, int $stream, string $payload): string
{
    return substr(pack('N', strlen($payload)), 1) . chr($type) . chr($flags) . pack('N', $stream & 0x7fffffff) . $payload;
}

function h2_lit(string $name, string $value): string
{
    return "\x00" . chr(strlen($name)) . $name . chr(strlen($value)) . $value;
}

function h2_payload(): string
{
    $out = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . h2_frame(4, 0, 0, pick(['', pack('nN', 4, mt_rand(0, 70000)), pack('nN', 5, mt_rand(0, 1 << 25))]));
    for ($i = mt_rand(1, 6); $i > 0; $i--) {
        $sid = mt_rand(0, 3) === 0 ? mt_rand(0, 9) : 2 * mt_rand(0, 20) + 1;
        switch (mt_rand(0, 9)) {
        case 0:
        case 1:
        case 2:
            $hdr = "\x82\x86" . h2_lit(':path', pick(['/', '/a', '/x?y=1', '/' . str_repeat('p', mt_rand(1, 3000))])) .
                h2_lit(':authority', 'x') . (mt_rand(0, 3) === 0 ? h2_lit('cookie', str_repeat('c=d;', mt_rand(1, 300))) : '');
            if (mt_rand(0, 4) === 0) {
                $hdr = mutate($hdr);
            }
            $out .= h2_frame(1, pick([4, 5, 4, 0x24, 0x2c, 0]), $sid, $hdr);
            break;
        case 3:
        case 4:
            $out .= h2_frame(0, pick([0, 1, 8, 9]), $sid, random_bytes(mt_rand(0, 20000)));
            break;
        case 5:
            $out .= h2_frame(3, 0, $sid, pack('N', mt_rand(0, 13)));
            break;
        case 6:
            $out .= h2_frame(8, 0, pick([0, $sid]), pack('N', pick([0, 1, 65535, 0x7fffffff, mt_rand(0, 1 << 30)])));
            break;
        case 7:
            $out .= h2_frame(6, pick([0, 1]), 0, random_bytes(pick([8, 8, 7, 9])));
            break;
        case 8:
            $out .= h2_frame(7, 0, 0, pack('NN', mt_rand(0, 9), mt_rand(0, 13)));
            break;
        default:
            $out .= h2_frame(mt_rand(0, 12), mt_rand(0, 255), $sid, random_bytes(mt_rand(0, 40)));
        }
    }
    return $out;
}

function one_client(int $http_port, int $tcp_port, array &$stat): void
{
    $kind = mt_rand(0, 5);
    if ($kind === 4) {
        if (defined('SWOOLE_SSL')) {
            ssl_client($http_port + 400, $stat);
        }
        return;
    }
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
    case 5:
        $payload = h2_payload();
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

putenv('SWOOLE_CLOSE_FUZZ=' . json_encode(compact('http_port', 'tcp_port', 'logfile', 'bigfile', 'seed', 'pidfile')));
$server_process = new Process(function () use ($http_port, $tcp_port, $mode, $logfile, $bigfile, $seed, $pidfile) {
    server_main($http_port, $tcp_port, $mode, $logfile, $bigfile, $seed, $pidfile);
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
$stat = ['connected' => 0, 'connect_fail' => 0, 'health_fail' => 0, 'exceptions' => 0, 'reload' => 0, 'kill_worker' => 0];
$failed = false;

run(function () use ($duration, $http_port, $tcp_port, &$stat, $server_pid, &$failed, $pidfile, $mode_name, $logfile) {
    $end = microtime(true) + $duration;
    $concurrency = 32;
    $running = 0;
    $last_health = $last_usage = microtime(true);
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
        // Occasionally reload the server or SIGKILL a worker while connections are in flight.
        $dice = mt_rand(0, 4000);
        if ($dice === 0) {
            Process::kill($server_pid, SIGUSR1);
            $stat['reload']++;
        } elseif ($dice === 1 && $mode_name !== 'thread') {
            $pids = array_filter(array_map('intval', @file($pidfile) ?: []));
            $victim = $pids ? pick(array_slice($pids, -4)) : 0;
            if ($victim > 1 && $victim !== $server_pid && Process::kill($victim, 0)) {
                Process::kill($victim, SIGKILL);
                $stat['kill_worker']++;
            }
        }
        // Safety net so a runaway server cannot exhaust the machine.
        if (microtime(true) - $last_usage > 1) {
            $last_usage = microtime(true);
            [$rss, $procs, $threads] = tree_usage($server_pid);
            if ($rss > 3072 || $procs > 24 || $threads > 400) {
                echo "FAIL: resource limit exceeded (rss={$rss}MB procs=$procs threads=$threads)\n";
                Process::kill($server_pid, SIGKILL);
                $failed = true;
                return;
            }
        }
        if (microtime(true) - $last_health > 2) {
            $last_health = microtime(true);
            if ($stat['connected'] === 0 && $stat['connect_fail'] > 500) {
                echo "FAIL: server never accepted a connection\n";
                $failed = true;
                return;
            }
            clearstatcache(true, $logfile);
            // A spinning event loop floods the log (and the disk) within seconds.
            if (@filesize($logfile) > 256 << 20) {
                echo "FAIL: server log exceeds 256MB (event loop spinning?)\n";
                $failed = true;
                return;
            }
            if (!Process::kill($server_pid, 0)) {
                echo "FAIL: server master is gone\n";
                $failed = true;
                return;
            }
            if (!healthy($http_port + 800)) {
                $stat['health_fail']++;
                echo "WARN: health probe failed\n";
            }
        }
    }
    while ($running > 0) {
        Coroutine::sleep(0.05);
    }
    for ($i = 0; $i < 5 && !healthy($http_port + 800); $i++) {
        Coroutine::sleep(0.5);
    }
    if (!healthy($http_port + 800)) {
        echo "FAIL: server does not answer after the run\n";
        $failed = true;
        if (getenv('FUZZ_HOLD')) {
            // Keep the hung server alive so that its state can be inspected from another shell.
            file_put_contents(dirname($logfile) . "/HELD", (string) $server_pid);
            Coroutine::sleep((int) getenv('FUZZ_HOLD'));
        }
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
// Workers deliberately SIGKILLed by the driver are expected to be reported.
if (preg_match('/abnormal exit, status=\d+, signal=(?!9\b)\d+/', $log)) {
    echo "FAIL: log contains 'abnormal exit'\n";
    $failed = true;
}
foreach (['Segmentation', 'SIGSEGV', 'Aborted', 'AddressSanitizer', 'Assertion', 'double free', 'corrupt'] as $marker) {
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
if (getenv('FUZZ_KEEP_ON_EXIT_TIMEOUT') && stripos($log, 'worker exit timeout') !== false) {
    echo "NOTE: worker exit timeout seen (workdir kept: $workdir)\n";
    exit(0);
}
array_map('unlink', glob("$workdir/*"));
@rmdir($workdir);
