--TEST--
swoole_client_sync: preserve complete and partial length frames between recv calls
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Client;
use SwooleTest\Assert;

function connectFramedClient(int $port, int $type): Client
{
    $client = new Client($type);
    Assert::true($client->set([
        'open_length_check' => true,
        'package_length_func' => static function (string $data): int {
            return strlen($data) < 4 ? 0 : unpack('N', $data)[1];
        },
        'package_max_length' => 64,
    ]));
    Assert::true($client->connect('127.0.0.1', $port, 1));
    return $client;
}

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) explode(':', stream_socket_get_name($server, false))[1];
$client = connectFramedClient($port, SWOOLE_SOCK_TCP);
$peer = stream_socket_accept($server, 1);
Assert::resource($peer);
stream_set_write_buffer($peer, 0);
$first = pack('N', 8) . 'One!';
$second = pack('N', 8) . 'Two!';

// Include a complete second frame, a partial header and a partial body.
foreach ([strlen($second), 2, 6] as $prefix) {
    Assert::same(fwrite($peer, $first . substr($second, 0, $prefix)), strlen($first) + $prefix);
    Assert::same($client->recv(), $first);
    $remainder = substr($second, $prefix);
    if ($remainder !== '') {
        Assert::same(fwrite($peer, $remainder), strlen($remainder));
    }
    Assert::same($client->recv(), $second);
}
$client->close();
fclose($peer);

$keep = SWOOLE_SOCK_TCP | SWOOLE_KEEP;
$client = connectFramedClient($port, $keep);
$peer = stream_socket_accept($server, 1);
Assert::resource($peer);
stream_set_write_buffer($peer, 0);
Assert::same(fwrite($peer, $first . $second), strlen($first . $second));
Assert::same($client->recv(), $first);
Assert::true($client->close());

$client = connectFramedClient($port, $keep);
Assert::same($client->reuseCount, 0);
$client->close(true);
fclose($peer);
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
