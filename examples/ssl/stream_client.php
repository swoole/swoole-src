<?php
$contextOptions = [
    'ssl' => [
        'verify_peer' => false,
//        'allow_self_signed' => true,
//        'cafile' => __DIR__.'/privkey.pem',
        'peer_name' => 'example.com',
    ]
];
$context = stream_context_create($contextOptions);

$fp = stream_socket_client("ssl://127.0.0.1:9501", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
if (!$fp)
{
    die("Unable to connect: $errstr ($errno)");
}

stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_SSLv23_CLIENT);
$ret = fwrite($fp, "hello\n");
var_dump($ret);

$recv =  fread($fp, 8192);
var_dump($recv);
echo "finish\n";

