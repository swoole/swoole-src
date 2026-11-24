<?php
require __DIR__ . '/certs.php';
$client = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);

$client->set(array(
    'ssl_cert_file' => SSL_CERT_DIR . 'client-cert.pem',
    'ssl_key_file' => SSL_CERT_DIR . 'client-key.pem',
//     'ssl_cert_file' => SSL_CERT_DIR . 'client.crt',
//     'ssl_key_file' => SSL_CERT_DIR . 'client.key',
    'ssl_allow_self_signed' => true,
    'ssl_verify_peer' => true,

    'ssl_cafile' => SSL_CERT_DIR . 'ca-cert.pem',
));
if (!$client->connect('127.0.0.1', 9501, -1))
{
    exit("connect failed. Error: {$client->errCode}\n");
}
echo "connect ok\n";
$client->send("hello world-" . str_repeat('A', $i) . "\n");
echo $client->recv();
