<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 1:00
 */

namespace com\skplanet\jose\util;


class Base64UrlSafeEncoderTest extends \PHPUnit_Framework_TestCase
{
    public function testEncode()
    {
        $expect = 'YXBwbGU';
        $actual = Base64UrlSafeEncoder::encode('apple');

        printf("%s\n", $actual);

        $this->assertEquals($expect, $actual);
    }

    public function testDecode()
    {
        $expected = 'apple';
        $actual = Base64UrlSafeEncoder::decode('YXBwbGU');

        printf("%s\n", $actual);

        $this->assertEquals($expected, $actual);
    }
}
