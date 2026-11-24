<?php
// This example writes a temporary file; remove it on exit to keep the tree clean.
register_shutdown_function(function () {
    foreach (glob(__DIR__ . '/resp.html') as $file) {
        @unlink($file);
    }
});
$sock = stream_socket_client("tcp://127.0.0.1:9501");
fwrite($sock, file_get_contents(__DIR__ . '/httpdata'));
stream_set_chunk_size($sock, 2*1024*1024);
$data = fread($sock, 8192 * 128);
if ($argv[1] == 'save')
{
    file_put_contents(__DIR__ . "/resp.html", $data);
}
else
{
    echo $data;
}
