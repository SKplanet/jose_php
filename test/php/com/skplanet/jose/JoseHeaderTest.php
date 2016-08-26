<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 1:05
 */

namespace com\skplanet\jose;


use com\skplanet\jose\jwa\Jwa;

class JoseHeaderTest extends \PHPUnit_Framework_TestCase
{
    public function testToString()
    {
        $expect = '{"alg":"A128KW","enc":"A128CBC-HS256","kid":"test"}';
        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);
        $joseHeader->setKid('test');

        $actual = $joseHeader;

        $this->assertEquals($expect, $actual);

        printf("%s\n%s\n", $expect, $actual);
    }

    public function testSerialize()
    {
        $expect = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoidGVzdCJ9';

        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);
        $joseHeader->setKid('test');

        $this->assertEquals($expect, $joseHeader->serialize());
        printf("%s\n", $joseHeader->serialize());
    }

    public function testDeserialize()
    {
        $expect = '{"alg":"A128KW","enc":"A128CBC-HS256","kid":"test"}';

        $data = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoidGVzdCJ9';

        $joseHeader = new JoseHeader();
        $joseHeader->deserialize($data);

        $this->assertEquals($expect, $joseHeader);
        printf("%s\n", $joseHeader);
    }
}
