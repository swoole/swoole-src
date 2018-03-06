--TEST--
swoole_coroutine: swoole_http_server getRuid
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; 
if (!method_exists( 'Swoole\Coroutine', 'getRuid')) { exit("swoole feature http_receive_uid is needed."); }
?>
--FILE--

<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl_concurrency.php";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)  {
    $r = curl_concurrency(['http://127.0.0.1:9501', 'http://127.0.0.1:9501']);

    assert($r == ['[OK] rid:2; cid:4', '[OK] rid:3; cid:5']);
    echo 'two requests with uid 2,3; four coroutine with uid 2,3,4,5';

    swoole_process::kill($pid);
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", 9501);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function ($request, $response) {

        $r= \Swoole\Coroutine::getRuid();

        co::sleep(3);

        go(function () use($r, $response) {
	    if($r===\Swoole\Coroutine::getRuid()){
             $response->end('[OK] '.  'rid:' .  \Swoole\Coroutine::getRuid() ."; " .  'cid:' .  \Swoole\Coroutine::getuid() );
	    }else{
             $response->end( '[NO] '. 'rid:' .  \Swoole\Coroutine::getRuid() ."; " .  'cid:' .  \Swoole\Coroutine::getuid() );
	    }
	});
	

    });

    $http->start();
};

$pm->childFirst();
$pm->run();


?>

--EXPECTREGEX--
.*two requests with uid 2,3; four coroutine with uid 2,3,4,5.+
