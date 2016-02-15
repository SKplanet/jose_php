<?php

/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오전 11:23
 */

use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\alg\Aes128KeyWrap;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\jwa\JwaFactory;
use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\util\Base64UrlSafeEncoder;
use com\skplanet\jose\util\ByteUtils;


class JweDeserializerTest extends PHPUnit_Framework_TestCase
{
    public function testParseHeader()
    {
        $expected = 'Live long and prosper.';
        $key = Base64UrlSafeEncoder::decode("GawgguFyGrWKav7AX4VKUg");
        $src = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ';

        $jweSerialize = new JweSerializer(JoseActionType::DESERIALIZE, $src, $key);
        $joseHeader = $jweSerialize->getJoseHeader();

        $this->assertEquals(Jwa::A128KW, $joseHeader->getAlg());
        $this->assertEquals(Jwa::A128CBC_HS256, $joseHeader->getEnc());

        $actual = $jweSerialize->compactSeriaization($src);
        $this->assertEquals($expected, $actual);
    }
}
