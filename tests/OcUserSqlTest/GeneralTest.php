<?php

namespace OcUserSqlTest;

use \PHPUnit_Framework_TestCase;

class GeneralTest extends PHPUnit_Framework_TestCase
{
    public function setup ()
    {}

    public function testBackendInitCorrect()
    {
        $backend = $this->getMockBuilder('OC_USER_SQL')
                        ->disableOriginalConstructor()
                        ->getMock();

        $valueNameRequested=array();
        $backend->expects($this->any())
             ->method('getAppValueWrapper')
             ->will($this->returnCallback(function ($appName,$valueName,$default) use($valueNameRequested) {
                 if ( $appName !== 'user_sql' ) {
                     continue;
                 }
                 $valueNameRequested[$valueName]=true;
                 return $valueName;
             }));


        $rBackendInit= new \ReflectionMethod($backend, 'init');
        $rBackendInit->setAccessible(true);

        $attributeList = array('sql_host','sql_username','sql_database','sql_password','sql_table',
                'sql_column_username','sql_column_password','sql_column_displayname',
                'sql_column_active','sql_type','default_domain','strip_domain','crypt_type');


        // call default init
        $rBackendInit->invoke($backend);


        // start assert
        $this->assertGreaterThanOrEqual(13,count($valueNameRequested));

        foreach ( $attributeList as $attribute ) {
            $this->assertObjectHasAttribute($attribute, $backend);

            // give read access
            $rBackendProperty= new \ReflectionProperty($backend, $attribute);
            $rBackendProperty->setAccessible(true);

            $this->assertEqual( $attribute, $rBackendProperty->getValue($backend) );
        }
    }
}
