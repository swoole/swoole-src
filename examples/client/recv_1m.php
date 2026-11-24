<?php
// This example writes a temporary file; remove it on exit to keep the tree clean.
register_shutdown_function(function () {
    foreach (glob(__DIR__ . '/data.log') as $file) {
        @unlink($file);
    }
});
$c = new Swoole\Client(SWOOLE_TCP);
$f = fopen(__DIR__ . '/data.log', 'w');
$c->connect('127.0.0.1', 9509, 60);
$c->send("AAAAAAAAAAAAAAAA");

$n_bytes = 0;

while (true)
{
    $line = $c->recv();
    if ($line === false)
    {
        echo "recv failed.\n";
        break;
    }
    elseif (empty($line))
    {
        echo "recv $n_bytes bytes\n";
        break;
    }
    else
    {
        fwrite($f, $line);
        $n_bytes += strlen($line);
    }
}
