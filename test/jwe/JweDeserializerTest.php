<?php

/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오전 11:23
 */

use syruppay\jose\JoseActionType;
use syruppay\jose\jwa\Jwa;
use syruppay\jose\jwe\JweSerializer;
use syruppay\jose\util\Base64UrlSafeEncoder;


class JweDeserializerTest extends PHPUnit_Framework_TestCase
{
    public function testParseHeader()
    {
        $expected = 'Live long and prosper.';
        $key = Base64UrlSafeEncoder::decode("GawgguFyGrWKav7AX4VKUg");
        $src = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ';

        $jweSerialize = new JweSerializer();
        $jweSerialize->setKey($key);
        $jweSerialize->setParse($src);
        $joseHeader = $jweSerialize->getJoseHeader();

        $this->assertEquals(Jwa::A128KW, $joseHeader->getAlg());
        $this->assertEquals(Jwa::A128CBC_HS256, $joseHeader->getEnc());

        $actual = $jweSerialize->compactDeserialization();
        $this->assertEquals($expected, $actual);
    }
}
