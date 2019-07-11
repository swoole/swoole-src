--TEST--
swoole_feature/full_duplex: socket
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const CHUNK_SIZE = 128 * 1024; // 128K
const CHUNK_NUM = 8; // 1M
const BUFFER_SIZE = CHUNK_SIZE / 2; // 64K

$pm = new ProcessManager;
$pm->initRandomDataEx(MAX_CONCURRENCY_LOW, MAX_REQUESTS_LOW, CHUNK_SIZE);
$pm->parentFunc = function ($pid) use ($pm) {
    global $closer;
    $closer = go(function () {
        $closer = co::getCid();
        $timer = Swoole\Timer::after(10 * 1000, function () use ($closer) {
            echo "TIMEOUT\n";
            co::resume($closer);
        });
        co::yield();
        if (Swoole\Timer::exists($timer)) {
            Swoole\Timer::clear($timer);
        }
        global $sockets;
        foreach ($sockets as $socket) {
            $socket->close();
        }
    });
    for ($c = 0; $c < MAX_CONCURRENCY_LOW; $c++) {
        go(function () use ($pm, $c) {
            global $sockets;
            $sockets[] = $socket = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            $ret = $socket->connect('127.0.0.1', $pm->getFreePort(), -1);
            if (!Assert::assert($ret)) {
                throw new RuntimeException('connect failed');
            } else {
                set_socket_coro_buffer_size($socket, BUFFER_SIZE);
            }
            // read
            go(function () use ($pm, $socket, $c) {
                for ($n = 0; $n < MAX_REQUESTS_LOW; $n++) {
                    // id
                    if (!$socket->send(tcp_head($c))) {
                        break;
                    }
                    // length
                    if (!$socket->send(tcp_head(CHUNK_SIZE * CHUNK_NUM, 'N'))) {
                        break;
                    }
                    // data
                    $data = $pm->getRandomDataEx($c);
                    for ($p = CHUNK_NUM; $p--;) {
                        $send_n = 0;
                        do {
                            $n_bytes = $socket->send(substr($data, $send_n));
                            if (!$n_bytes) {
                                break;
                            }
                            $send_n += $n_bytes;
                        } while ($send_n !== CHUNK_SIZE);
                    }
                }
            });
            // write
            go(function () use ($pm, $socket) {
                while ($data = $socket->recv(tcp_type_length(), -1)) {
                    global $count, $closer;
                    @$count[tcp_length($data)]++;
                    if (array_sum($count) === MAX_CONCURRENCY_LOW * MAX_REQUESTS_LOW * CHUNK_NUM) {
                        phpt_var_dump($count);
                        co::resume($closer);
                    }
                }
            });
        });
    }
    swoole_event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::assert($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::assert($server->listen(MAX_CONCURRENCY));
        while ($conn = $server->accept(-1)) {
            if (!Assert::assert($conn instanceof Co\Socket)) {
                throw new RuntimeException('accept failed');
            } else {
                set_socket_coro_buffer_size($conn, BUFFER_SIZE);
            }
            go(function () use ($pm, $conn) {
                while (true) {
                    // id
                    $head = $conn->recv(tcp_type_length(), -1);
                    if (!$head || ($id = tcp_length($head)) < 0) {
                        break;
                    }
                    // length
                    $length = tcp_length($conn->recv(tcp_type_length('N'), -1), 'N');
                    // data
                    $verify = $pm->getRandomDataEx($id);
                    do {
                        $data = '';
                        $need_n = CHUNK_SIZE;
                        do {
                            $data .= $conn->recv($need_n, -1);
                            $need_n = CHUNK_SIZE - strlen($data);
                        } while ($need_n !== 0);
                        if (!Assert::assert($data === $verify)) {
                            break;
                        }
                        $length -= strlen($data);
                        $conn->send(tcp_head($id));
                    } while ($length > 0);
                }
            });
        }
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
