--TEST--
swoole_curl/multi: HTTP/2 upload flow-control stall does not busy loop
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_constant_not_defined('CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE');
skip('libcurl has no HTTP/2 support', !(curl_version()['features'] & CURL_VERSION_HTTP2));
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Runtime;
use SwooleTest\ProcessManager;

const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const TRANSFER_TIMEOUT_MS = 500;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

    Swoole\Coroutine\run(function () use ($pm) {
        $multi = curl_multi_init();
        $handle = curl_init("http://127.0.0.1:{$pm->getFreePort()}/duplex-stall");

        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => str_repeat('x', 2 * 1024 * 1024),
            CURLOPT_TIMEOUT_MS => TRANSFER_TIMEOUT_MS,
            CURLOPT_NOPROXY => '*',
        ]);
        Assert::same(curl_multi_add_handle($multi, $handle), CURLM_OK);

        $active = null;
        $selectCount = 0;
        $readyCount = 0;

        do {
            do {
                $mrc = curl_multi_exec($multi, $active);
            } while ($mrc === CURLM_CALL_MULTI_PERFORM);

            if ($active > 0) {
                // Let the reactor observe the socket once while curl_multi_select() is not
                // waiting. The selector must restore CURL_POLL_INOUT as both READ and WRITE.
                if ($selectCount === 0) {
                    Swoole\Coroutine\System::sleep(0.001);
                }
                ++$selectCount;
                $selected = curl_multi_select($multi, 0.05);
                if ($selected > 0) {
                    ++$readyCount;
                } elseif ($selected === -1) {
                    usleep(1000);
                }
            }
        } while ($active > 0);

        $message = curl_multi_info_read($multi);
        Assert::same($message['result'], CURLE_OPERATION_TIMEDOUT);
        Assert::lessThan($selectCount, 100);
        Assert::lessThan($readyCount, 50);
        Assert::lessThan(curl_getinfo($handle, CURLINFO_SIZE_UPLOAD), 65536);

        curl_multi_remove_handle($multi, $handle);
        curl_close($handle);
        curl_multi_close($multi);
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle(function (Connection $connection) use ($server) {
            // Advertise the default 65535-byte stream window and never replenish it.
            $connection->send(http2_frame(4, 0, 0));

            $buffer = '';
            $prefaceReceived = false;
            $requestHeadersReceived = false;

            while (!$requestHeadersReceived) {
                $data = $connection->recv();
                if ($data === '' || $data === false) {
                    break;
                }
                $buffer .= $data;

                if (!$prefaceReceived) {
                    if (strlen($buffer) < strlen(HTTP2_PREFACE)) {
                        continue;
                    }
                    Assert::same(substr($buffer, 0, strlen(HTTP2_PREFACE)), HTTP2_PREFACE);
                    $buffer = substr($buffer, strlen(HTTP2_PREFACE));
                    $prefaceReceived = true;
                }

                while (strlen($buffer) >= 9) {
                    $length = unpack('N', "\0" . substr($buffer, 0, 3))[1];
                    if (strlen($buffer) < 9 + $length) {
                        break;
                    }

                    $type = ord($buffer[3]);
                    $streamId = unpack('N', substr($buffer, 5, 4))[1] & 0x7fffffff;
                    $buffer = substr($buffer, 9 + $length);

                    if ($type === 1 && $streamId === 1) {
                        $requestHeadersReceived = true;
                        break;
                    }
                }
            }

            if ($requestHeadersReceived) {
                // SETTINGS ACK followed by a 200 response without END_STREAM.
                // 0x88 is the HPACK static-table entry for ":status: 200".
                $connection->send(http2_frame(4, 1, 0) . http2_frame(1, 4, 1, "\x88"));
                Swoole\Coroutine\System::sleep(1);
            }

            $connection->close();
            $server->shutdown();
        });

        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
