--TEST--
swoole_http2_server: internal writers drain end and sendfile without turning synchronous callbacks into coroutines
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

class FlowHeaderValue
{
    public function __construct(private ?Swoole\Http\Response $response = null)
    {
    }

    public function __toString(): string
    {
        Assert::same(Swoole\Coroutine::getCid(), -1);
        if ($this->response !== null) {
            $this->response->header('x-during-conversion', 'added');
            $this->response = null;
        }
        return 'saved';
    }
}

class FlowHeaderThrows
{
    public function __toString(): string
    {
        throw new RuntimeException('header conversion');
    }
}

class DeleteFlowFile
{
    public function __construct(private string $file)
    {
    }

    public function __toString(): string
    {
        unlink($this->file);
        return 'deleted';
    }
}

class RetryFlowHeader
{
    public static int $calls = 0;

    public function __toString(): string
    {
        ++self::$calls;
        Assert::same(Swoole\Coroutine::getCid(), -1);
        return 'retry';
    }
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        $file = tempnam(sys_get_temp_dir(), 'swoole-http2-sync-');
        file_put_contents($file, 'prefix' . str_repeat('F', 70000) . 'suffix');
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $tls, $file) {
            try {
                $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                $peer->request(1, '/end');
                $peer->request(3, '/file');
                $peer->barrier();
                Assert::same($peer->total, 0);
                Assert::false(file_exists($file));
                $peer->update(1, 70000);
                $peer->update(3, 70000);
                while ($peer->total < 65535) {
                    $peer->read();
                }
                $peer->barrier();
                Assert::same($peer->total, 65535);
                $peer->update(0, 140000 - 65535);
                while (!isset($peer->ended[1], $peer->ended[3])) {
                    $peer->read();
                }
                Assert::same($peer->bodies[1], str_repeat('E', 70000));
                Assert::same($peer->bodies[3], str_repeat('F', 70000));
                $peer->update(0, 2);
                $peer->request(5, '/reject');
                $peer->update(5, 2);
                $peer->bytes(5, 2);
                Assert::same($peer->bodies[5], 'OK');
                $peer->settings(2);
                $peer->update(0, 2);
                $peer->request(7, '/retry-file');
                $peer->bytes(7, 2);
                while (!isset($peer->ended[7])) {
                    $peer->read();
                }
                Assert::same($peer->bodies[7], 'OK');
                $peer->close();

                $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                $peer->request(1, '/blocked');
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 7);
                Assert::same(unpack('N', substr($frame['payload'], 4, 4))[1], 0);
                $peer->closed();
                $peer->close();
                $peer = new Http2FlowPeer($pm->getFreePort(), 65535, $tls);
                $peer->request(1, '/alive');
                $peer->bytes(1, 2);
                Assert::same($peer->bodies[1], 'OK');
                $peer->close();
            } finally {
                $pm->kill();
                if (file_exists($file)) {
                    unlink($file);
                }
            }
        };
        $pm->childFunc = function () use ($pm, $mode, $tls, $file) {
            http2_flow_server($pm, $mode, function ($request, $response) use ($file) {
                Assert::same(Swoole\Coroutine::getCid(), -1);
                switch ($request->server['request_uri']) {
                    case '/end':
                        $response->header('x-value', [new FlowHeaderValue($response), 'literal']);
                        $response->trailer = ['x-trailer' => new FlowHeaderValue()];
                        $data = str_repeat('E', 70000);
                        Assert::true($response->end($data));
                        $data[0] = 'Z'; // The pending writer must retain its own string reference.
                        $response->trailer['x-trailer'] = new FlowHeaderThrows();
                        break;
                    case '/file':
                        Assert::true($response->sendfile($file, 6, 70000, true));
                        break;
                    case '/reject':
                        $response->header('x-value', new FlowHeaderThrows());
                        try {
                            $response->end('not sent');
                            Assert::true(false, 'expected the header conversion exception in this callback');
                        } catch (RuntimeException $e) {
                            Assert::same($e->getMessage(), 'header conversion');
                            $response->header = [];
                            Assert::true($response->end('OK'));
                        }
                        break;
                    case '/retry-file':
                        $failedFile = tempnam(sys_get_temp_dir(), 'swoole-http2-open-');
                        file_put_contents($failedFile, 'file');
                        $response->header('x-value', new DeleteFlowFile($failedFile));
                        Assert::false($response->sendfile($failedFile));
                        Assert::true($response->isWritable());
                        $response->header('x-value', new RetryFlowHeader());
                        Assert::true($response->write('OK'));
                        Assert::same(RetryFlowHeader::$calls, 1);
                        Assert::true($response->end());
                        break;
                    case '/blocked':
                        Assert::true($response->end(str_repeat('B', 70000)));
                        break;
                    default:
                        Assert::true($response->end('OK'));
                }
                Assert::false($response->isWritable());
                Assert::same(Swoole\Coroutine::getCid(), -1);
            }, $tls, ['enable_coroutine' => false, 'send_timeout' => 0.5]);
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
