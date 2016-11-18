<?php
define('OUTPUT_DIR', __DIR__ . '/src');

function isPHPKeyword($word)
{
    $keywords = array('exit', 'die', 'echo', 'class', 'interface', 'function', 'public', 'protected', 'private');

    return in_array($word, $keywords);
}

function getFunctionsDef(array $funcs, $version)
{
    $all = '';
    foreach ($funcs as $k => $v)
    {
        /**
         * @var $v ReflectionMethod
         */
        $comment = '';
        $vp = array();
        $params = $v->getParameters();
        if ($params)
        {
            $comment = "/**\n";
            foreach ($params as $k1 => $v1)
            {
                if ($v1->isOptional())
                {
                    $comment .= " * @param $" . $v1->name . "[optional]\n";
                    $vp[] = '$' . $v1->name . '=null';
                }
                else
                {
                    $comment .= " * @param $" . $v1->name . "[required]\n";
                    $vp[] = '$' . $v1->name;
                }
            }
            $comment .= " * @return mixed\n";
            $comment .= " */\n";
        }
        $comment .= sprintf("function %s(%s){}\n\n", $k, join(', ', $vp));
        $all .= $comment;
    }

    return $all;
}

function getConstantsDef(array $consts)
{
    $all = "";
    $sp4 = str_repeat(' ', 4);
    foreach ($consts as $k => $v)
    {
        $all .= "{$sp4}const {$k} = $v;\n";
    }
    return $all;
}

function getMethodsDef(array $methods, $version)
{
    $all = '';
    $sp4 = str_repeat(' ', 4);
    foreach ($methods as $k => $v)
    {
        /**
         * @var $v ReflectionMethod
         */
        if ($v->isFinal())
        {
            continue;
        }

        $method_name = $v->name;
        if (isPHPKeyword($method_name))
        {
            $method_name = '_' . $method_name;
        }

        $comment = '';
        $vp = array();
        $comment = "$sp4/**\n";

        $params = $v->getParameters();
        if ($params)
        {
            foreach ($params as $k1 => $v1)
            {
                if ($v1->isOptional())
                {
                    $comment .= "$sp4 * @param $" . $v1->name . "[optional]\n";
                    $vp[] = '$' . $v1->name . '=null';
                }
                else
                {
                    $comment .= "$sp4 * @param $" . $v1->name . "[required]\n";
                    $vp[] = '$' . $v1->name;
                }
            }
        }
        $comment .= "$sp4 * @return mixed\n";
        $comment .= "$sp4 */\n";
        $modifiers = implode(
            ' ', Reflection::getModifierNames($v->getModifiers())
        );
        $comment .= sprintf(
            "$sp4%s function %s(%s){}\n\n", $modifiers, $method_name, join(', ', $vp)
        );
        $all .= $comment;
    }

    return $all;
}

function exportNamespaceClass($class)
{
    $ns = explode('\\', $class);
    if (strtolower($ns[0]) != 'swoole')
    {
        return;
    }

    array_walk($ns, function (&$v, $k) use (&$ns)
    {
        $v = ucfirst($v);
    });

    $path = OUTPUT_DIR . '/namespace/' . implode('/', array_slice($ns, 1));

    $dir = dirname($path);
    $name = basename($path);

    if (!is_dir($dir))
    {
        mkdir($dir, 0777, true);
    }
    $content = "<?php\nnamespace Swoole;\n\nclass ";
    $content .= ucfirst($name) . ' extends \\' . str_replace('\\', '_', $class) . ' { }';
    file_put_contents($path . '.php', $content);
}

function exportExtension($ext)
{
    $rf_ext = new ReflectionExtension($ext);
    $funcs = $rf_ext->getFunctions();
    $classes = $rf_ext->getClasses();
    $consts = $rf_ext->getConstants();
    $version = $rf_ext->getVersion();
    $defines = '';

    $fdefs = getFunctionsDef($funcs, $version);
    $class_def = '';
    foreach ($consts as $k => $v)
    {
        if (!is_numeric($v))
        {
            $v = "'$v'";
        }
        $defines .= "define('$k',$v);\n";
    }
    foreach ($classes as $k => $v)
    {
        if (strchr($k, '\\'))
        {
            exportNamespaceClass($k);
            continue;
        }

        $prop_str = '';
        $props = $v->getProperties();
        array_walk(
            $props, function ($v, $k)
        {
            global $prop_str, $sp4;
            $modifiers = implode(
                ' ', Reflection::getModifierNames($v->getModifiers())
            );
            $prop_str .= "$sp4/**\n$sp4*@var $" . $v->name . " " . $v->class
                . "\n$sp4*/\n$sp4 $modifiers  $" . $v->name . ";\n\n";
        }
        );
        if ($v->getParentClass())
        {
            $k .= ' extends ' . $v->getParentClass()->name;
        }
        $modifier = 'class';
        if ($v->isInterface())
        {
            $modifier = 'interface';
        }
        //获取常量定义
        $consts = getConstantsDef($v->getConstants());
        //获取方法定义
        $mdefs = getMethodsDef($v->getMethods(), $version);
        $class_def .= sprintf(
            "/**\n*@since %s\n*/\n%s %s\n{\n%s\n%s\n%s\n}\n", $version, $modifier, $k,
            $consts, $prop_str, $mdefs
        );
    }
    file_put_contents(
        OUTPUT_DIR . '/mixed.php', "<?php\n" . $defines . $fdefs . $class_def
    );
}

exportExtension('swoole');
echo "swoole version: " . swoole_version() . "\n";
echo "dump success.\n";

