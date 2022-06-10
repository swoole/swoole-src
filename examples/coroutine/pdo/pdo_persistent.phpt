<?php
Co\run(function () {
    $pdo = new PDO(
        "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
        MYSQL_SERVER_USER, MYSQL_SERVER_PWD,
        array(PDO::ATTR_PERSISTENT => true)
    );
    echo "connected\n";
    sleep(30);
    echo "sleep 30\n";
    $pdo->exec("SELECT sleep(1)");
});

echo "DONE\n";
