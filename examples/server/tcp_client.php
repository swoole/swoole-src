<?php
$client = new swoole_client(SWOOLE_SOCK_TCP);

if (!$client->connect('127.0.0.1', 9504)) {
    exit("connect failed\n");
}

$func = "send_test" . intval(empty($argv[1]) ? 3 : $argv[1]);

for ($l = 0; $l < 1; $l++) {
    $data = '';
    for ($i = 0; $i < 10; $i++) {
        $len = rand(100000, 200000);
        echo "send : " . ($len + 4) . "\n";
        send_test3($client, $len);
    }
}

function send_test3($client, $len)
{
    $data = pack('N', $len + 4);
    $data .= str_repeat('A', $len) . rand(1000, 9999);
    $chunks = str_split($data, 4000);
    foreach ($chunks as $ch) {
        $client->send($ch);
    }
//    $data = $client->recv();
//    echo "recv : " . strlen($data) . "\n";
}
