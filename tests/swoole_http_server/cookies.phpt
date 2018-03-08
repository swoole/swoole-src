--TEST--
swoole_http_server: cookies
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

$cookies = array (
    '8MLP_5753_saltkey' => 'RSU8HYED',
    '8MLP_5753_lastvisit' => '1426120671',
    'attentiondomain' => '2z.cn,chinaz.com,kuaishang.cn,cxpcms.com',
    '8MLP_5753_security_cookiereport' => 'c014Hgufskpv55xgM9UaB/ZZdMrcN0QqBYdcGomTu8OlTDWzTA0z',
    '8MLP_5753_ulastactivity' => 'e4a1aRIbgdzoRDd8NlT5CMIwLnWjyjr2hWyfn6T5g82RitUOdf3o',
    'mytool_user' => 'uSHVgCUFWf5Sv2Y8tKytQRUJW3wMVT3rw5xQLNGQFIsod4C6vYWeGA==',
    'PHPSESSID' => 't3hp9h4o8rb3956t5pajnsfab1',
    '8MLP_5753_st_p' => '1024432|1428040399|f7599ba9053aa27e12e9e597a4c372ce',
    '8MLP_5753_st_t' => '1024432|1428040402|46d40e02d899b10b431822eb1d39f6a1',
    '8MLP_5753_forum_lastvisit' => 'D_140_1427103032D_165_1427427405D_168_1427870172D_167_1427870173D_166_1428021390D_163_1428040402',
    '8MLP_5753_sid' => 'k25gxK',
    'cmstop_page-view-mode' => 'view',
    'cmstop_rememberusername' => 'error',
    'cmstop_auth' => 'Jcn2qzVn9nsjqtodER9OphcW3PURDWNx6mO7j0Zbb9k=',
    'cmstop_username' => 'error',
    'Hm_lvt_aecc9715b0f5d5f7f34fba48a3c511d6' => '1427967317,1428021376,1428036617,1428040224',
    'Hm_lpvt_aecc9715b0f5d5f7f34fba48a3c511d6' => '1428050417',
    'YjVmNm_timeout' => '0',
);

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($cookies) {
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', 9501, 1))
    {
        exit("connect failed. Error: {$client->errCode}\n");
    }
    $header = "GET /index.php HTTP/1.1\r\n";
    $header .= "Host: 127.0.0.1\r\n";
    $header .= "Connection: keep-alive\r\n";
    $header .= "Cache-Control: max-age=0\r\n";

    $cookieStr = '';
    foreach($cookies as $k => $v)
    {
        $cookieStr .= "$k=$v; ";
    }
    $cookieStr .= "end=1";
    $cookies['end'] = "1";

    $header .= "Cookie: $cookieStr\r\n";
    $header .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
    $header .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n";
    $header .= "\r\n";
    $_sendStr = $header;

    $client->send($_sendStr);
    $data = $client->recv();
    $client->close();

    list(, $_respCookieStr) = explode("\r\n\r\n", $data);

    $respCookie = json_decode($_respCookieStr, true);
    assert($respCookie == $cookies);

    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);

    $http->set(['log_file' => '/dev/null']);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function ($request, $response) {
        $response->end(json_encode($request->cookie));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--

