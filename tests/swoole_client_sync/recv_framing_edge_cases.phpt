--TEST--
swoole_client_sync: recv() framing edge cases for length and eof protocols
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function serve($pm, int $port, array $chunks): void
{
    $server = stream_socket_server("tcp://127.0.0.1:$port");
    $pm->wakeup();
    $conn = stream_socket_accept($server, 10);
    foreach ($chunks as $chunk) {
        fwrite($conn, $chunk);
        usleep(30000);
    }
    fclose($conn);
}

function run(array $set, array $chunks, int $count): array
{
    $port = get_one_free_port();
    $pm = new ProcessManager;
    $pm->parentFunc = function ($pid) use ($port, $set, $count, &$result) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        $client->set($set);
        Assert::true($client->connect('127.0.0.1', $port, 5));
        $result = [];
        for ($i = 0; $i < $count; $i++) {
            $result[] = $client->recv();
        }
        $client->close();
    };
    $pm->childFunc = function () use ($pm, $port, $chunks) {
        serve($pm, $port, $chunks);
    };
    $pm->childFirst();
    $pm->run();
    return $result;
}

$length = ['open_length_check' => true, 'package_length_type' => 'N', 'package_length_offset' => 0,
    'package_body_offset' => 4, 'package_max_length' => 64];
$pack = fn($s) => pack('N', strlen($s)) . $s;

// header and body split across segments, then two packets in one segment
$r = run($length, [substr($pack('hello'), 0, 2), substr($pack('hello'), 2), $pack('a') . $pack('bc')], 3);
Assert::same(array_map('substr', $r, [4, 4, 4]), ['hello', 'a', 'bc']);

// peer closes in the middle of the header: empty string, no stale buffer reuse
$r = run($length, ["\x00\x00"], 1);
Assert::same($r, ['']);

// oversized packet is rejected
$r = run($length, [pack('N', 1000) . 'x'], 1);
Assert::same($r, ['']);

// eof: fragmented eof and several packets per segment
$eof = ['open_eof_check' => true, 'package_eof' => "\r\n", 'package_max_length' => 64];
$r = run($eof, ["ab\r", "\ncd\r\nef\r\n"], 3);
Assert::same($r, ["ab\r\n", "cd\r\n", "ef\r\n"]);

// eof: no terminator within package_max_length
$r = run($eof, [str_repeat('x', 100)], 1);
Assert::same($r, [false]);
echo "DONE\n";
?>
--EXPECTF--
%A
DONE
