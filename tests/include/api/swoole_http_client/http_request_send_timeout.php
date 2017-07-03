<?php
function request_send_timeout($host, $port)
{
    $httpClient = new swoole_http_client($host, $port);
    $httpClient->on("timeout", function(swoole_http_client $httpClient) {
        echo "timeout\n";
        $httpClient->close();
    });

    $httpClient->setReqTimeout(1);
    $httpClient->get("/", function ($client)  {
        assert(false);
    });
}
