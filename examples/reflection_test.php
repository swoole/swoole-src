<?php

$Ref_swoole_server = new ReflectionClass('swoole_server');
$methods = $Ref_swoole_server->getMethods();
foreach($methods as $method) {
    echo "----------------------------------------" .PHP_EOL;
    echo "method name : " . $method->name . PHP_EOL;
    echo "----------------------------------------" . PHP_EOL;
    $method = $Ref_swoole_server->getMethod($method->name);
    $params = $method->getParameters();
    print_r($params);
}

