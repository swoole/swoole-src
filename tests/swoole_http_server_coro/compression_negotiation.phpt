--TEST--
swoole_http_server_coro: negotiate compression weights and preserve Vary fields
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';
require __DIR__ . '/../include/http_compression_negotiation.inc';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $server->set(['http_compression_min_length' => 128, 'http_compression_types' => ['text/html']]);
    $server->handle('/', 'compression_negotiation_response');
    Coroutine::create(fn () => $server->start());
    try {
        compression_negotiation_test($server->port);
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
