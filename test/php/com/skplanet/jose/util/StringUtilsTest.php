<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 2:02
 */

namespace com\skplanet\jose\util;


class StringUtilsTest extends \PHPUnit_Framework_TestCase
{
    public function testStr2hex()
    {
        echo StringUtils::str2hex('123');
    }
}
