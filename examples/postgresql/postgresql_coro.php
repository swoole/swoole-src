
<?php

go(function () {

    $pg = new Swoole\Coroutine\PostgreSql();
    $conn  = $pg -> connect ("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu password=");
    $result = $pg->query($conn, 'SELECT * FROM test;');
    $arr = $pg->fetchAll($result);// the same with affectedRows(),fetchObject(),fetchAssoc(),fetchArray(),fetchRow()
    var_dump($arr);
    //$numRows = $pg->numRows($result);
    //var_dump($numRows);

});

go(function () {

    $pg = new Swoole\Coroutine\PostgreSql();
    $conn  = $pg -> connect ("host=127.0.0.1 port=5432 dbname=test user=wuzhenyu password=");
    $metaData = $pg->metaData($conn, 'test');
    var_dump($metaData);

});
?>
