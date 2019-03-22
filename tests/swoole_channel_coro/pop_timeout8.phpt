--TEST--
swoole_channel_coro: pop timeout 8
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$c1 = new chan();

class T {
    public $c;
    function __construct()
    {
        $this->c = new chan();
        echo "__construct\n";
    }

    function __destruct()
    {
        go(function(){
            echo "__destruct\n";
            $ret = $this->c->pop(0.5);
            echo "pop ret:".var_export($ret,1)." error:".$this->c->errCode."\n";
        });

    }
}
$t = new T();
unset($t);
?>
--EXPECTF--
__construct
__destruct
pop ret:false error:-1
