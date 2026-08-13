--TEST--
swoole_windows: embedded library uses portable errno values
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\FastCGI\Client::class, false)) {
    die('skip embedded library not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\FastCGI\Client;
use Swoole\Coroutine\FastCGI\Client\Exception as ClientException;
use Swoole\Coroutine\Socket;
use Swoole\FastCGI\Request;

use function Swoole\Coroutine\run;

class ControlledClient extends Client
{
    public function replaceSocket(Socket $socket): void
    {
        $this->socket = $socket;
    }
}

class ControlledClientSocket extends Socket
{
    public function __construct(private readonly string $packet)
    {
        parent::__construct(AF_INET, SOCK_STREAM, IPPROTO_IP);
    }

    public function sendAll(string $data, float $timeout = 0): int|false
    {
        return strlen($data);
    }

    public function recvPacket(float $timeout = 0): string|false
    {
        return $this->packet;
    }

    public function close(): bool
    {
        return true;
    }
}

run(function () {
    foreach ([['', SWOOLE_ERRNO_ECONNRESET], ['short', SWOOLE_ERRNO_EPROTO]] as [$packet, $expectedCode]) {
        $client = new ControlledClient('127.0.0.1');
        $client->replaceSocket(new ControlledClientSocket($packet));
        $caught = false;

        try {
            $client->execute(new Request());
        } catch (ClientException $exception) {
            $caught = true;
            Assert::same($expectedCode, $exception->getCode());
        }

        Assert::true($caught);
    }

    $socket = new Socket(AF_INET, SOCK_DGRAM);
    $buffer = null;
    $name   = null;
    $port   = null;
    Assert::false(swoole_socket_recvfrom($socket, $buffer, 0, 0, $name, $port));
    Assert::same(SWOOLE_ERRNO_EAGAIN, $socket->errCode);

    if (extension_loaded('sockets')) {
        Assert::notSame(SOCKET_ECONNRESET, SWOOLE_ERRNO_ECONNRESET);
    }
});

echo "DONE\n";
?>
--EXPECT--
DONE
