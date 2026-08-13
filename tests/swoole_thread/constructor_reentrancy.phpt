--TEST--
swoole_thread: constructors parse before native state
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Thread\Barrier;
use Swoole\Thread\Lock;

final class ReentrantHost
{
    public function __construct(private Server $server)
    {
    }

    public function __toString(): string
    {
        $this->server->__construct('127.0.0.1', 0, SWOOLE_BASE);

        return '127.0.0.1';
    }
}

$lock = new Lock(Lock::MUTEX);
$reentered = false;
set_error_handler(function () use ($lock, &$reentered): bool {
    $reentered = true;

    try {
        $lock->__construct(Lock::MUTEX);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Thread\Lock can only be called once');
    }

    return true;
});
try {
    try {
        $lock->__construct(3.5);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Thread\Lock can only be called once');
    }
} finally {
    restore_error_handler();
}
// Broken constructors reject before parameter parsing, so this is the discriminating assertion.
Assert::true($reentered);

$barrier = new Barrier(2);
$reentered = false;
set_error_handler(function () use ($barrier, &$reentered): bool {
    $reentered = true;

    try {
        $barrier->__construct(2);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Thread\Barrier can only be called once');
    }

    return true;
});
try {
    try {
        $barrier->__construct(2.5);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Thread\Barrier can only be called once');
    }
} finally {
    restore_error_handler();
}
// Broken constructors reject before parameter parsing, so this is the discriminating assertion.
Assert::true($reentered);

$server = (new ReflectionClass(Server::class))->newInstanceWithoutConstructor();
try {
    $server->__construct(new ReentrantHost($server), 0, SWOOLE_BASE);
    Assert::true(false);
} catch (Error $error) {
    Assert::contains($error->getMessage(), 'Constructor of Swoole\Server can only be called once');
}
?>
--EXPECT--
