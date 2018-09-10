--TEST--
swoole_coroutine: $this private access in PHP70
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
(new Bar)->foo();

class Bar
{
    private $private = 'private';
    protected $protect = 'protect';
    public $public = 'public';

    public function foo()
    {
        go(function () {
            co::sleep(.001);
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