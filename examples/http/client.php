<?php 
$cli = new swoole_client(SWOOLE_SOCK_TCP);
$cli->connect('127.0.0.1', 9501);

//$type = 'GET';
$type = 'POST';

$cookie = "8MLP_5753_saltkey=RSU8HYED; 8MLP_5753_lastvisit=1426120671; pgv_pvi=1454765056; CNZZDATA1000008050=684878078-1426123263-http%253A%252F%252Fcznews-team.chinaz.com%252F%7C1426485386; attentiondomain=2z.cn%2cchinaz.com%2ckuaishang.cn%2ccxpcms.com; CNZZDATA33217=cnzz_eid%3D1036784254-1426122273-http%253A%252F%252Fcznews-team.chinaz.com%252F%26ntime%3D1427414208; CNZZDATA433095=cnzz_eid%3D1613871160-1426123273-http%253A%252F%252Fcznews-team.chinaz.com%252F%26ntime%3D1427848205; CNZZDATA1254679775=309722566-1427851758-http%253A%252F%252Fcznews-team.chinaz.com%252F%7C1427851758; 8MLP_5753_security_cookiereport=c014Hgufskpv55xgM9UaB%2FZZdMrcN0QqBYdcGomTu8OlTDWzTA0z; 8MLP_5753_ulastactivity=e4a1aRIbgdzoRDd8NlT5CMIwLnWjyjr2hWyfn6T5g82RitUOdf3o; 8MLP_5753_auth=9351LJpv7Xa%2FPUylJDQgRiAONZ5HysOaj%2BqRGb6jYmpqZpRkVc2ibPXm7LAfArC%2FpIpY2Fx%2B59AHqzr843qozZWxWNZi; mytool_user=uSHVgCUFWf5Sv2Y8tKytQRUJW3wMVT3rw5xQLNGQFIsod4C6vYWeGA==; 8MLP_5753_lip=220.160.111.22%2C1428036585; pgv_si=s4245709824; PHPSESSID=t3hp9h4o8rb3956t5pajnsfab1; 8MLP_5753_st_p=1024432%7C1428040399%7Cf7599ba9053aa27e12e9e597a4c372ce; 8MLP_5753_viewid=tid_7701248; 8MLP_5753_smile=5D1; 8MLP_5753_st_t=1024432%7C1428040402%7C46d40e02d899b10b431822eb1d39f6a1; 8MLP_5753_forum_lastvisit=D_140_1427103032D_165_1427427405D_168_1427870172D_167_1427870173D_166_1428021390D_163_1428040402; 8MLP_5753_sid=k25gxK; 8MLP_5753_lastact=1428040403%09misc.php%09patch; cmstop_page-view-mode=view; cmstop_rememberusername=error; cmstop_auth=Jcn2qzVn9nsjqtodER9OphcW3PURDWNx6mO7j0Zbb9k%3D; cmstop_userid=6; cmstop_username=error; Hm_lvt_aecc9715b0f5d5f7f34fba48a3c511d6=1427967317,1428021376,1428036617,1428040224; Hm_lpvt_aecc9715b0f5d5f7f34fba48a3c511d6=1428050417; YjVmNm_timeout=0";

if ($type == 'GET')
{
    $header = "GET /home/explore/ HTTP/1.1\r\n";
    $header .= "Host: 127.0.0.1\r\n";
    $header .= "Connection: keep-alive\r\n";
    $header .= "Cache-Control: max-age=0\r\n";
    $header .= "Cookie: $cookie\r\n";
    $header .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
    $header .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n";
    $header .= "\r\n";
    $_sendStr = $header;
}
else
{
//    $header = "POST /home/explore/?hello=123&world=swoole#hello HTTP/1.1\r\n";
    $header = "POST /post.php HTTP/1.1\r\n";
    $header .= "Host: 127.0.0.1\r\n";
    $header .= "Referer: http://group.swoole.com/\r\n";
    $header .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $header .= "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2\r\n";
    $header .= "Cookie: pgv_pvi=9559734272; efr__Session=uddfvbm87dtdtrdsro1ohlt4o6; efr_r_uname=apolov%40vip.qq.com; efr__user_login=3N_b4tHW1uXGztWW2Ojf09vssOjR5abS4abO5uWRopnm0eXb7OfT1NbIoqjWzNCvodihq9qaptqfra6imtLXpNTNpduVoque26mniKej5dvM09WMopmmpM2xxcmhveHi3uTN0aegpaiQj8Snoa2IweHP5fCL77CmxqKqmZKp5ejN1c_Q2cPZ25uro6mWqK6BmMOzy8W8k4zi2d3Nlb_G0-PaoJizz97l3deXqKyPoKacr6ynlZ2nppK71t7C4uGarKunlZ-s; pgv_si=s8426935296; Hm_lvt_4967f2faa888a2e52742bebe7fcb5f7d=1410240641,1410241802,1410243730,1410243743; Hm_lpvt_4967f2faa888a2e52742bebe7fcb5f7d=1410248408\r\n";
    $header .= "RA-Ver: 2.5.3\r\n";
    $header .= "RA-Sid: 2A784AF7-20140212-113827-085a9c-c4de6e\r\n";

    $_postData = ['body1' => 'swoole_http-server', 'message' => 'nihao'];
    $_postBody = json_encode($_postData);
//    $_postBody = http_build_query($_postData);
    $header .=  "Content-Length: " . strlen($_postBody);
    echo "http header length=".strlen($header)."\n";
    $header .=  "Content-Length: " . (strlen($_postBody) - 2);

//    $cli->send($header);
//    usleep(100000);
    $_sendStr = $header . "\r\n\r\n" . $_postBody;
//    $_sendStr = "\r\n\r\n" . $_postBody;
    echo "postBody length=".strlen($_postBody)."\n";
}

echo "-------------------------Request----------------------------\n";
echo $_sendStr;
$cli->send($_sendStr);
echo "send ".strlen($_sendStr)." byte\n";

echo "-------------------------Response----------------------------\n";
$data = $cli->recv();
var_dump($data);
exit;
