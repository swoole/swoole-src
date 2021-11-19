<?php

$ref_server = new ReflectionClass('Swoole\Server');
$methods = $ref_server->getMethods();
foreach($methods as $method) {
    echo "----------------------------------------" .PHP_EOL;
    echo "method name : " . $method->name . PHP_EOL;
    echo "----------------------------------------" . PHP_EOL;
    $method = $ref_server->getMethod($method->name);
    $params = $method->getParameters();
    print_r($params);
}
