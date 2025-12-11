<?php
//$arr = [];
//$http = new Swoole\Http\Server("0.0.0.0", 9501);
//$http->set(array(
//    'worker_num' => 1,
//));
//$http->on('request', function ($request, $response) {
//startMemleakCheck();
//    static $i=0;
//    global $arr;
//    $arr[] = $i++;
//    print_r($arr);
//endMemleakCheck();
//    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
//});
//$http->start();
//
//
//
//

//class Test
class Test
{
    public $arr = [];

    //问题的根源是run函数无法结束，所以run的局部变量和此函数所属的对象也应该是全局变量
    function run()
    {
        $locals = '';
        $this->run2($locals);
    }

    function run2(&$locals)
    {
        global $global1, $global2;
        $http = new \Swoole\Http\Server("0.0.0.0", 9501, SWOOLE_BASE);
        $http->set([
            'worker_num' => 1
        ]);
        $http->on("start", function ($server) {

        });
        $http->on("request", function ($req, $resp) use (&$global1, &$global2, &$locals) {
            $global2 .= "2222222222";
            $locals .= "333333333333";
            $global1[] = random_bytes(random_int(256, 4096));
            $this->arr[] = "444444444";
            // var_dump($global1, $global2, $run2var, $this->pro);
            $resp->end("hello world");

            swoole_tracer_leak_detect(128);
        });

        $http->start();
    }
}

(new Test())->run();


