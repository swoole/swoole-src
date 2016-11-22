<?php
define('OUTPUT_DIR', __DIR__ . '/output');
define('CONFIG_DIR', __DIR__ . '/config');
define('LANGUAGE', 'chinese');

class ExtensionDocument
{
    const EXTENSION_NAME = 'swoole';

    const C_METHOD = 1;
    const C_PROPERTY = 2;
    const C_CONSTANT = 3;
    const SPACE5 = '     ';

    /**
     * @var string
     */
    protected $version;

    /**
     * @var ReflectionExtension
     */
    protected $rf_ext;

    static function isPHPKeyword($word)
    {
        $keywords = array('exit', 'die', 'echo', 'class', 'interface', 'function', 'public', 'protected', 'private');

        return in_array($word, $keywords);
    }

    static function formatComment($comment)
    {
        $lines = explode("\n", $comment);
        foreach ($lines as &$li)
        {
            $li = ltrim($li);
            if ($li[0] != '*')
            {
                $li = self::SPACE5 . '*' . $li;
            }
            else
            {
                $li = self::SPACE5 . $li;
            }
        }
        return implode("\n", $lines)."\n";
    }

    static function getNamespaceAlias($className)
    {
        return str_replace(' ', '\\', ucwords(str_replace('_', ' ', $className)));
    }

    function getConfig($class, $name, $type)
    {
        switch($type)
        {
            case self::C_CONSTANT:
                $dir = 'constant';
                break;
            case self::C_METHOD:
                $dir = 'method';
                break;
            case self::C_PROPERTY:
                $dir = 'property';
                break;
            default:
                return false;
        }
        $file = CONFIG_DIR . '/' . LANGUAGE . '/' . strtolower($class) . '/' . $dir . '/' . $name . '.php';
        if (is_file($file))
        {
            return include $file;
        }
        else
        {
            return array();
        }
    }

    function getFunctionsDef(array $funcs)
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

    /**
     * @param $classname
     * @param array $consts
     * @return string
     */
    function getConstantsDef($classname, array $consts)
    {
        $all = "";
        $sp4 = str_repeat(' ', 4);
        foreach ($consts as $k => $v)
        {
            $all .= "{$sp4}const {$k} = ";
            if (is_int($v))
            {
                $all .= "{$v};\n";
            }
            else
            {
                $all .= "'{$v}';\n";
            }
        }
        return $all;
    }

    /**
     * @param $classname
     * @param array $methods
     * @return string
     */
    function getMethodsDef($classname, array $methods)
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
            if (self::isPHPKeyword($method_name))
            {
                $method_name = '_' . $method_name;
            }

            $vp = array();
            $comment = "$sp4/**\n";

            $config = $this->getConfig($classname, $method_name, self::C_METHOD);
            if (!empty($config['comment']))
            {
                $comment .= self::formatComment($config['comment']);
            }

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
            if (!isset($config['return']))
            {
                $comment .= self::SPACE5 . "* @return mixed\n";
            }
            elseif (!empty($config['return']))
            {
                $comment .= self::SPACE5 . "* @return {$config['return']}\n";
            }
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

    /**
     * @param $classname
     * @param $ref  ReflectionClass
     */
    function exportNamespaceClass($classname, $ref)
    {
        $ns = explode('\\', $classname);
        if (strtolower($ns[0]) != 'swoole')
        {
            return;
        }

        array_walk($ns, function (&$v, $k) use (&$ns)
        {
            $v = ucfirst($v);
        });


        $path = OUTPUT_DIR . '/namespace/' . implode('/', array_slice($ns, 1));

        $namespace = implode('\\', array_slice($ns, 0, -1));
        $dir = dirname($path);
        $name = basename($path);

        if (!is_dir($dir))
        {
            mkdir($dir, 0777, true);
        }

        $content = "<?php\nnamespace {$namespace};\n\n".$this->getClassDef($name, $ref);
        file_put_contents($path . '.php', $content);
    }

    /**
     * @param $classname string
     * @param $ref ReflectionClass
     * @return string
     */
    function getClassDef($classname, $ref)
    {
        $prop_str = '';
        $props = $ref->getProperties();
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
        if ($ref->getParentClass())
        {
            $classname .= ' extends \\' . $ref->getParentClass()->name;
        }
        $modifier = 'class';
        if ($ref->isInterface())
        {
            $modifier = 'interface';
        }
        //获取常量定义
        $consts = $this->getConstantsDef($classname, $ref->getConstants());
        //获取方法定义
        $mdefs = $this->getMethodsDef($classname, $ref->getMethods());
        $class_def = sprintf(
            "/**\n * @since %s\n */\n%s %s\n{\n%s\n%s\n%s\n}\n", $this->version, $modifier, $classname,
            $consts, $prop_str, $mdefs
        );
        return $class_def;
    }

    function __construct()
    {
        if (!extension_loaded(self::EXTENSION_NAME))
        {
            throw new \Exception("no ".self::EXTENSION_NAME." extension.");
        }
        $this->rf_ext = new ReflectionExtension(self::EXTENSION_NAME);
        $this->version = $this->rf_ext->getVersion();
    }

    function export()
    {
        /**
         * 获取所有define常量
         */
        $consts = $this->rf_ext->getConstants();
        $defines = '';
        foreach ($consts as $className => $ref)
        {
            if (!is_numeric($ref))
            {
                $ref = "'$ref'";
            }
            $defines .= "define('$className', $ref);\n";
        }
        file_put_contents(
            OUTPUT_DIR . '/constants.php', "<?php\n" . $defines
        );

        /**
         * 获取所有函数
         */
        $funcs = $this->rf_ext->getFunctions();
        $fdefs = $this->getFunctionsDef($funcs);
        file_put_contents(
            OUTPUT_DIR . '/functions.php', "<?php\n" . $fdefs
        );

        /**
         * 获取所有类
         */
        $classes = $this->rf_ext->getClasses();
        $class_alias = "<?php\n";
        foreach ($classes as $className => $ref)
        {
            //命名空间
            if (strchr($className, '\\'))
            {
                $this->exportNamespaceClass($className, $ref);
                continue;
            }
            //非命名空间
            else
            {
                $class_alias .= sprintf("\nclass %s extends %s\n{\n\n}\n", $className, self::getNamespaceAlias($className));
            }
        }
        file_put_contents(
            OUTPUT_DIR . '/classes.php', $class_alias
        );
    }
}

(new ExtensionDocument())->export();

echo "swoole version: " . swoole_version() . "\n";
echo "dump success.\n";
