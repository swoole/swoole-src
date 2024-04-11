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
    static private $s_private = 's_private';
    static protected $s_protect = 's_protect';
    static public $s_public = 's_public';

    private $private = 'private';
    protected $protect = 'protect';
    public $public = 'public';

    public function foo()
    {
        \Swoole\Runtime::setHookFlags(SWOOLE_HOOK_ALL);

        go(function () {
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            co::sleep(.001);
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        var_dump(self::$s_private);
        var_dump(self::$s_protect);
        var_dump(self::$s_public);
        var_dump($this->private);
        var_dump($this->protect);
        var_dump($this->public);
        go(function () {
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            $mysql = new mysqli();
            $res = $mysql->connect(
                MYSQL_SERVER_HOST,
                MYSQL_SERVER_USER,
                MYSQL_SERVER_PWD,
                MYSQL_SERVER_DB,
                MYSQL_SERVER_PORT,
            );
            Assert::assert($res);
            $ret = $mysql->query('show tables', 1)->fetch_all();
            Assert::assert(is_array($ret));
            Assert::assert(count($ret) > 0);
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        $cid = go(function () {
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            Co::yield();
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        go(function () use ($cid) {
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            Co::resume($cid);
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        go(function () {
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
            Co::sleep(0.001);
            var_dump(self::$s_private);
            var_dump(self::$s_protect);
            var_dump(self::$s_public);
            var_dump($this->private);
            var_dump($this->protect);
            var_dump($this->public);
        });
        var_dump(self::$s_private);
        var_dump(self::$s_protect);
        var_dump(self::$s_public);
        var_dump($this->private);
        var_dump($this->protect);
        var_dump($this->public);
    }
}

?>
--EXPECT--
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
string(9) "s_private"
string(9) "s_protect"
string(8) "s_public"
string(7) "private"
string(7) "protect"
string(6) "public"
