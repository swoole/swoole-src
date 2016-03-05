<?php



// echo $defines;

function getFuncDef(array $funcs,$version)
{
    $all='';
    foreach ($funcs as $k=>$v)
    {
        $comment='';
        $vp=array();
        $params=$v->getParameters();
        if($params)
        { 
            $comment="/**\n";
            foreach ($params as $k1=>$v1)
            {
                if($v1->isOptional())
                {
                    $comment.="* @param $".$v1->name."[optional]\n";
                    $vp[]='$'.$v1->name.'=null';
                }else{
                    $comment.="* @param $".$v1->name."[required]\n";
                    $vp[]='$'.$v1->name;
                }
            }
            $comment.="*/\n";
        }
        $comment.=sprintf("function %s(%s){}\n\n",$k,join(',', $vp));
         $all.=$comment;
    }
    return $all;
}

function getMethodsDef(array $methods,$version)
{
    $all='';
    $sp4=str_repeat(' ', 4);
    foreach ($methods as $k=>$v)
    {
        
        $comment='';
        $vp=array();
        
        $params=$v->getParameters();
        if($params)
        {
            $comment="$sp4/**\n";
            foreach ($params as $k1=>$v1)
            {
                if($v1->isOptional())
                {
                    $comment.="$sp4* @param $".$v1->name."[optional]\n";
                    $vp[]='$'.$v1->name.'=null';
                }else{
                    $comment.="$sp4* @param $".$v1->name."[required]\n";
                    $vp[]='$'.$v1->name;
                }
            }
            $comment.="$sp4*/\n";
        }
        $modifiers=implode(' ',Reflection::getModifierNames($v->getModifiers()));
        $comment.=sprintf("$sp4%s function %s(%s){}\n\n",$modifiers,$v->name,join(',', $vp));
        $all.=$comment;
    }
    return $all;
}
function export_ext($ext)
{
    $rf_ext=new ReflectionExtension($ext);
    $funcs=$rf_ext->getFunctions();
    $classes=$rf_ext->getClasses();
    $consts=$rf_ext->getConstants();
    $version=$rf_ext->getVersion();
    $defines='';
    $sp4=str_repeat(' ', 4);
    $fdefs=getFuncDef($funcs,$version);
    $class_def='';
    foreach ($consts as $k=>$v)
    {
        if(!is_numeric($v))
        {
            $v="'$v'";
        }
        $defines.="define('$k',$v);\n";
    }
    foreach ($classes as  $k=>$v)
    {
        $prop_str='';
        $props=$v->getProperties();
        array_walk($props, function($v,$k){
            global $prop_str,$sp4;
            $modifiers=implode(' ',Reflection::getModifierNames($v->getModifiers()));
            $prop_str.="$sp4/**\n$sp4*@var $".$v->name." ".$v->class."\n$sp4*/\n$sp4 $modifiers  $".$v->name.";\n\n";
        });
        if($v->getParentClass())
        {
            $k.=' extends '.$v->getParentClass()->name;
        }
        $modifier='class';
        if($v->isInterface())
        {
            $modifier='interface';
        }
         $mdefs=getMethodsDef($v->getMethods(),$version);
         $class_def.=sprintf("/**\n*@since %s\n*/\n%s %s{\n%s%s\n}\n",$version,$modifier,$k,$prop_str,$mdefs);
    }
    if(!file_exists('./ext'))
    {
        mkdir('./ext',777,TRUE);
    }
   
    file_put_contents("./ext/".$ext.".php","<?php\n".$defines.$fdefs.$class_def);
}
function export_all_ext()
{
    $exts=get_loaded_extensions();
    foreach ($exts as $k=>$v) 
    {
        export_ext($v);
    }
}
export_all_ext();
echo swoole_version();

