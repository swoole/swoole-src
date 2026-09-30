--TEST--
swoole_curl: CurlManager cleans up CLI server failures
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use SwooleTest\CurlManager;

class TestCurlManager extends CurlManager
{
    public $serverPid;
    public $serverAvailable = true;

    public function getUrlBase()
    {
        return $this->serverAvailable ? parent::getUrlBase() : 'invalid://';
    }

    protected function runCliServer($port)
    {
        $process = parent::runCliServer($port);
        $this->serverPid = $process->pid;

        return $process;
    }

    protected function stopCliServer(Process $process)
    {
        $this->serverPid = $process->pid;
        parent::stopCliServer($process);
    }
}

$cm = new TestCurlManager();
try {
    $cm->run(function (): void {
        throw new RuntimeException('expected');
    });
    Assert::true(false);
} catch (RuntimeException $e) {
    Assert::same($e->getMessage(), 'expected');
}

Assert::false(@Process::kill($cm->serverPid, 0));
if (function_exists('pcntl_waitpid')) {
    Assert::same(pcntl_waitpid($cm->serverPid, $status, WNOHANG), -1);
}

$cm = new TestCurlManager();
$cm->serverAvailable = false;
try {
    $cm->run(function (): void {
        Assert::true(false);
    });
    Assert::true(false);
} catch (RuntimeException $e) {
    Assert::same($e->getMessage(), 'PHP CLI server did not become ready');
}

Assert::false(@Process::kill($cm->serverPid, 0));
if (function_exists('pcntl_waitpid')) {
    Assert::same(pcntl_waitpid($cm->serverPid, $status, WNOHANG), -1);
}

echo "DONE\n";
?>
--EXPECT--
DONE
