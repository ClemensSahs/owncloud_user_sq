<?php

if (isset($classMap)) {
    $classMap=array();
}
$classMap['OC_USER_SQL'] = __DIR__ .  '/src/user_sql.php';
$classMap['SplClassLoader'] = __DIR__ .  '/vendor/Spl/SplClassLoader.php';


$autoloadFunctionClassMap = function ($className) use ($classMap) {

    if ( !isset($classMap[$className]) ) {
        return false;
    }
    if (!file_exists($classMap[$className])) {
        return false;
    }

    require_once $classMap[$className];
    return class_exists($className,false);
};

spl_autoload_register($autoloadFunctionClassMap);

$splClassLoader= new SplClassLoader('Symfony\Component\EventDispatcher',__DIR__ . '/vendor');
$splClassLoader->register();

$splClassLoader= new SplClassLoader('postfixadmin',__DIR__ . '/vendor');
$splClassLoader->register();
