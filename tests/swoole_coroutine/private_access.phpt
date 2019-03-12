--TEST--
swoole_coroutine: $this private access in PHP70 (EG(scope))
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
(new Bar)->foo();

class Bar
{
    private $private = 'private';
    protected $protect = 'protect';
    public $public = 'public';

    public function foo()
    {
        go(function () {
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            co::sleep(.001);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        var_dump($this->private);
        var_dump($this->protect);
        var_dump($this->public);
        go(function () {
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            $mysql = new Swoole\Coroutine\MySQL;
            $res = $mysql->connect([
                'host' => MYSQL_SERVER_HOST,
                'port' => MYSQL_SERVER_PORT,
                'user' => MYSQL_SERVER_USER,
                'password' => MYSQL_SERVER_PWD,
                'database' => MYSQL_SERVER_DB
            ]);
            assert($res);
            $ret = $mysql->query('show tables', 1);
            assert(is_array($ret));
            assert(count($ret) > 0);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        $cid = go(function () {
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            Co::yield();
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        go(function () use ($cid) {
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            Co::resume($cid);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        var_dump($this->private);
        var_dump($this->protect);
        var_dump($this->public);
    }
}

?>
--EXPECT--
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(7) "private"
string(7) "protect"
string(6) "public"
