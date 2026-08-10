--TEST--
swoole_curl: CurlManager reaps the CLI server after exceptions
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

    public $serverLog;

    protected function runCliServer()
    {
        $process         = parent::runCliServer();
        $this->serverPid = $process->pid;
        $this->serverLog = $this->serverLogFile;

        return $process;
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
Assert::false(Process::wait(false));
Assert::false(file_exists($cm->serverLog));

echo "DONE\n";
?>
--EXPECT--
DONE
