<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);
if(!$client->connect('127.0.0.1', 9501))
{
    exit("connect fail\n");
}

//for ($l=0; $l < 100; $l++) 
{ 
    $datas = array();
    for($i=0; $i< 10; $i++) 
    {
        $body = '';
        $bodyLen = rand(1, 10);
        for ($j=0; $j < $bodyLen; $j++) 
        {
            $body .= pack('s', $j);
        }
        $data = pack('ss', $i, strlen($body));
        $data .= $body;

        $protocol = unpack('s*', $data);
        $output = '>> ';
        foreach ($protocol as $k=>$v) 
        {
            $output .= sprintf('%d,', $v);
        }
        echo $output . "\n";
        $datas[] = $data;
    }
    //一次发送20个包
    echo 'total send size:', strlen(implode('', $datas)),"\n";
    $client->send(implode('', $datas));
    sleep(1);
}
