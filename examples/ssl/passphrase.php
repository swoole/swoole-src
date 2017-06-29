<?php
$client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
$client->set(array(
    "ssl_key_file" => __DIR__ . '/ssl.key',
    "ssl_cert_file" => __DIR__ . '/ssl.crt',
    'ssl_passphrase' => '5524001',
));
if (!$client->connect('127.0.0.1', 9501, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}
echo "connect ok\n";
sleep(1);

for ($i = 0; $i < 1000; $i++)
{
    $client->send("hello world-" . str_repeat('A', $i) . "\n");
    echo $client->recv();
}
sleep(1);
