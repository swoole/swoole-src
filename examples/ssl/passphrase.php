<?php
require __DIR__ . '/certs.php';
$client = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
$client->set(array(
    "ssl_key_file" => SSL_CERT_DIR . 'server.key',
    "ssl_cert_file" => SSL_CERT_DIR . 'server.crt',
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
