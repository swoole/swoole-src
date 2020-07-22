--TEST--
swoole_http_client_coro: The bug of the filename parameter of download()
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
class C1
{
    protected $f;

    protected $savedFileName;

    public function __construct($f)
    {
        $this->f = $f;
    }

    public function withSavedFileName($savedFileName)
    {
        $self = clone $this;
        $self->savedFileName = $savedFileName;
        return $self;
    }

    public function getSavedFileName()
    {
        return $this->savedFileName;
    }

}

function download($pm, $fileName)
{
    $basename = substr($fileName, 0, -2);
    $fileName = $basename . '.jpg';
    $c1 = new C1($fileName);
    $c1 = $c1->withSavedFileName($fileName);

    $client = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
    $client->set(['timeout' => 5]);

    $client->download('/', $fileName);
}

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use($pm) {
        download($pm, '/tmp/test-1.*');
    });
    
    Co\run(function () use($pm) {
        download($pm, '/tmp/test-2.*');
    });

    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->sendfile(TEST_IMAGE);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
