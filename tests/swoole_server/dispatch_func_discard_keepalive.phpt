--TEST--
swoole_server: discarded framed packets preserve the connection for subsequent packets
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Server;
use function Swoole\Coroutine\run;

foreach ([false, true] as $lengthProtocol) {
    $discarded = new Atomic();
    $received = new Atomic();
    $closes = new Atomic();
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $lengthProtocol, $discarded, $received, $closes) {
        run(function () use ($pm, $lengthProtocol, $discarded, $received, $closes) {
            $client = new Client(SWOOLE_SOCK_TCP);
            $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            $frame = function (string $data) use ($lengthProtocol): string {
                return $lengthProtocol ? pack('N', strlen($data)) . $data : $data . "\r\n";
            };
            // The parser must advance past a discarded packet within a coalesced read.
            $data = $frame('drop') . $frame('keep');
            Assert::same($client->send($data), strlen($data));
            Assert::same($client->recv(), "keep\n");
            // A fragmented packet can be discarded without affecting the following packet.
            $drop = $frame('drop');
            Assert::same($client->send(substr($drop, 0, 2)), 2);
            Coroutine::sleep(0.001);
            $data = substr($drop, 2) . $frame('next');
            Assert::same($client->send($data), strlen($data));
            Assert::same($client->recv(), "next\n");
            Assert::same($discarded->get(), 2);
            Assert::same($received->get(), 2);
            Assert::same($closes->get(), 0);
            $client->close();
            $deadline = microtime(true) + 5;
            while ($closes->get() === 0 && microtime(true) < $deadline) {
                Coroutine::sleep(0.001);
            }
            Assert::same($closes->get(), 1);
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $lengthProtocol, $discarded, $received, $closes) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $settings = [
            'worker_num' => 2,
            'reactor_num' => 2,
            'log_file' => '/dev/null',
            'dispatch_func' => function (Server $server, int $fd, int $type, string $data) use ($discarded) {
                if (strpos($data, 'drop') !== false) {
                    $discarded->add();
                    return SWOOLE_DISPATCH_RESULT_DISCARD_PACKET;
                }
                return SWOOLE_DISPATCH_RESULT_USERFUNC_FALLBACK;
            },
        ];
        if ($lengthProtocol) {
            $settings += [
                'open_length_check' => true,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 4,
            ];
        } else {
            $settings += ['open_eof_split' => true, 'package_eof' => "\r\n"];
        }
        $server->set($settings);
        $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
            if ($workerId === 0) {
                $pm->wakeup();
            }
        });
        $server->on('receive', function (Server $server, int $fd, int $reactorId, string $data) use ($lengthProtocol, $received) {
            $body = $lengthProtocol ? substr($data, 4) : substr($data, 0, -2);
            Assert::true($body === 'keep' || $body === 'next');
            $received->add();
            Assert::true($server->send($fd, $body . "\n"));
        });
        $server->on('close', function () use ($closes) { $closes->add(); });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
