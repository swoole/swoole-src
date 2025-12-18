<?php
$username = "";
$password = "";

function test()
{
    $file = __DIR__ . "/test.mdb";
    $dsn = "odbc:Driver=MDBTools;DBQ=$file";
    $pdo = new \PDO($dsn);
    var_dump($pdo);
}

Co::set(['trace_flags' => SWOOLE_TRACE_CO_ODBC, 'log_level' => SWOOLE_LOG_DEBUG]);

Co\run(function () {
    test();
});
