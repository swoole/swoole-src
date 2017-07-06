<?php
function main() {
$cli = new \swoole_http_client("11.11.11.11", 9000);

$cli->on('close', function($cli) {
    assert(false);
});

$cli->on('error', function($cli) {
    echo "error";
});

$cli->get('/', function(swoole_http_client $cli) {});
}

main();
