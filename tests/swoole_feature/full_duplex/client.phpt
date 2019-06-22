--TEST--
swoole_feature/full_duplex: client
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
        global $clients;
        foreach ($clients as $client) {
            $client->close();
        }
    });
    for ($c = 0; $c < MAX_CONCURRENCY_LOW; $c++) {
        go(function () use ($pm, $c) {
            global $clients;
            $clients[] = $client = new Co\Client(SWOOLE_SOCK_TCP);
            $ret = $client->connect('127.0.0.1', $pm->getFreePort(), -1);
            if (!Assert::assert($ret)) {
                throw new RuntimeException('connect failed');
            } else {
                set_socket_coro_buffer_size($client->exportSocket(), BUFFER_SIZE);
                $client->set([
                    'open_eof_check' => true,
                    'package_eof' => "\n"
                ]);
            }
            // read
            go(function () use ($pm, $client, $c) {
                for ($n = 0; $n < MAX_REQUESTS_LOW; $n++) {
                    // id
                    if (!$client->send(tcp_head($c))) {
                        break;
                    }
                    // length
                    if (!$client->send(tcp_head(CHUNK_SIZE * CHUNK_NUM, 'N'))) {
                        break;
                    }
                    // data
                    $data = $pm->getRandomDataEx($c);
                    for ($p = CHUNK_NUM; $p--;) {
                        $send_n = 0;
                        do {
                            $n_bytes = $client->send(substr($data, $send_n));
                            if (!$n_bytes) {
                                break;
                            }
                            $send_n += $n_bytes;
                        } while ($send_n !== CHUNK_SIZE);
                    }
                }
            });
            // write
            go(function () use ($pm, $client) {
                while (($id = $client->recv(-1))) {
                    global $count, $closer;
                    $id = rtrim($id);
                    @$count[$id]++;
                    if (array_sum($count) === MAX_CONCURRENCY_LOW * MAX_REQUESTS_LOW * CHUNK_NUM) {
                        phpt_var_dump($count);
                        co::resume($closer);
                        echo "DONE\n";
                    }
                }
            });
        });
    }
    swoole_event::wait();
    $pm->kill();
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
                            $tmp = $conn->recv($need_n, -1);
                            if (!$tmp) {
                                break;
                            }
                            $data .= $tmp;
                            $need_n = CHUNK_SIZE - strlen($data);
                        } while ($need_n !== 0);
                        if (!Assert::assert($data === $verify)) {
                            break;
                        }
                        $length -= strlen($data);
                        $conn->send("{$id}\n");
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
