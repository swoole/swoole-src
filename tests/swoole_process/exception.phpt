--TEST--
swoole_process: exception
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

abstract class AbstractProcess
{
    public abstract function run();

    public abstract function onException(Throwable $e);

    public function start()
    {
        $process = new Swoole\Process(function (Swoole\Process $process) {
            swoole_event_add($process->pipe, function (Swoole\Process $process) { });
            try {
                $this->run();
            } catch (Throwable $e) {
                $this->onException($e);
            }
        });
        $process->start();
    }
}

class Process6 extends AbstractProcess
{
    public function run()
    {
        AAAA();
    }

    public function onException(Throwable $e)
    {
        throw $e;
    }
}

(new Process6())->start();

?>
--EXPECTF--
Fatal error: Uncaught Error: Call to undefined function AAAA() in %s:%d
Stack trace:
#0 %s(%d): Process6->run()
#1 [internal function]: AbstractProcess->{closure}(Object(Swoole\Process))
#2 %s(%d): Swoole\Process->start()
#3 %s(%d): AbstractProcess->start()
#4 {main}
  thrown in %s on line %d
