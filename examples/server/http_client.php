<?php 
$cli = new swoole_client(SWOOLE_SOCK_TCP);
$cli->connect('127.0.0.1', 9501);

$body = "Host: group.swoole.com\r\n";
$body .= "Connection: keep-alive\r\n";
$body .= "Cache-Control: max-age=0\r\n";
$body .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
$body .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n";


$body2 = "Referer: http://group.swoole.com/\r\n";
$body2 .= "Accept-Encoding: gzip,deflate,sdch\r\n";
$body2 .= "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2\r\n";
$body2 .= "Cookie: pgv_pvi=9559734272; efr__Session=uddfvbm87dtdtrdsro1ohlt4o6; efr_r_uname=apolov%40vip.qq.com; efr__user_login=3N_b4tHW1uXGztWW2Ojf09vssOjR5abS4abO5uWRopnm0eXb7OfT1NbIoqjWzNCvodihq9qaptqfra6imtLXpNTNpduVoque26mniKej5dvM09WMopmmpM2xxcmhveHi3uTN0aegpaiQj8Snoa2IweHP5fCL77CmxqKqmZKp5ejN1c_Q2cPZ25uro6mWqK6BmMOzy8W8k4zi2d3Nlb_G0-PaoJizz97l3deXqKyPoKacr6ynlZ2nppK71t7C4uGarKunlZ-s; pgv_si=s8426935296; Hm_lvt_4967f2faa888a2e52742bebe7fcb5f7d=1410240641,1410241802,1410243730,1410243743; Hm_lpvt_4967f2faa888a2e52742bebe7fcb5f7d=1410248408\r\n";
$body2 .= "RA-Ver: 2.5.3\r\n";
$body2 .= "RA-Sid: 2A784AF7-20140212-113827-085a9c-c4de6e\r\n";



//-------------------------------POST------------------------------
$http_post1 = "POST /home/explore/?hello=123&world=swoole#hello HTTP/1.1\r\n";
$_postBody = http_build_query(['body1' => 'swoole_http-server', 'message' => 'nihao']);
$_sendStr = $http_post1.$body.$body2."Content-Length: ".strlen($_postBody)."\r\n\r\n".$_postBody;

$cli->send($_sendStr);
echo "send ".strlen($_sendStr)." byte\n";
$data = $cli->recv();
var_dump($data);
exit;

//-------------------------------GET------------------------------
$http_get1 = "GET /home/explore/ HTTP/1.1\r\n";
$cli->send($http_get1.$body);
echo "send ".strlen($http_get1.$body)." byte\n";
sleep(1);
$cli->send($http_get2."\r\n");
echo "send ".strlen($body2)." byte\n";
$data = $cli->recv();

var_dump($data);