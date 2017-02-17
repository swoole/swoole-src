<?php
function test()
{
    //var_dump(func_get_args());
    return array("hello world\n", "women", "tolx");
}

class Test2
{
    public $value = 1234;

    function __construct()
    {
      echo "class Test2 __construct\n";
      var_dump(func_get_args());
    }

    function hello()
    {
      echo __CLASS__.": ".__LINE__."\n";
    }
}

class Test
{
  public $name = "Test";
  public $hello = "";

    function abc()
    {
      var_dump(func_get_args());
      var_dump($this->hello);
      return array("key" => 'rango', 'value' => 'tianfeng');
    }
}

function test2()
{
  return new Test();
}

$module = swoole_load_module(__DIR__.'/test.so');

$s = microtime(true);
for($i =0; $i< 1; $i++)
{
    //$ret = swoole_strerror(11);
    $ret = $module->cppMethod("abc", 1234, 459.55, "hello");
}
echo "use ".(microtime(true) - $s)."s\n";
var_dump($ret);

//sleep(1000);
