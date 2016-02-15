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
use com\skplanet\jose\jwa\enc\ContentEncryptKeyGenerator;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\jwa\JwaFactory;
use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\util\Base64UrlSafeEncoder;
use com\skplanet\jose\util\ByteUtils;

class JweSerializerTest extends PHPUnit_Framework_TestCase
{
    public function testJoseHeaderAndSerialize()
    {
        $expected = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0';

        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);
        $actual = $joseHeader->serialize();

        $this->assertEquals($expected, $actual);
    }

    public function testContentEncryption()
    {
        $expected = '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ';

        //04d31fc5549dfcfe0b649dfa3faa6ace6b7cd42d6f6b09dbc8b100f08f9c2ccf
        $cek = ByteUtils::convertHalfWordArrayToBin(
                array(4, 211, 31, 197, 84, 157, 252,
                254, 11, 100, 157, 250, 63, 170, 106,
                206, 107, 124, 212, 45, 111, 107, 9,
                219, 200, 177, 0, 240, 143, 156, 44, 207));

        //19ac2082e1721ab58a6afec05f854a52
        $key = Base64UrlSafeEncoder::decode('GawgguFyGrWKav7AX4VKUg');

        $cekGenerator = new ContentEncryptKeyGenerator(32);
        $cekGenerator->setUserEncryptionKey($cek);

        $aesKeyWrap = new Aes128KeyWrap(16);
        $jweAlgResult = $aesKeyWrap->encryption($key, $cekGenerator);

        $this->assertEquals($expected, Base64UrlSafeEncoder::encode($jweAlgResult->getEncryptedCek()));
    }

    public function testSerialize()
    {
        $cek = ByteUtils::convertHalfWordArrayToBin(
                array(4, 211, 31, 197, 84, 157, 252,
				    254, 11, 100, 157, 250, 63, 170, 106,
				    206, 107, 124, 212, 45, 111, 107, 9,
				    219, 200, 177, 0, 240, 143, 156, 44, 207));

		$key = Base64UrlSafeEncoder::decode("GawgguFyGrWKav7AX4VKUg");

		$iv = ByteUtils::convertHalfWordArrayToBin(
                array(3, 22, 60, 12, 43, 67, 104, 105,
				    108, 108, 105, 99, 111, 116, 104, 101));

		$src = ByteUtils::convertHalfWordArrayToBin(
                array(76, 105, 118, 101, 32, 108, 111, 110,
				    103, 32, 97, 110, 100, 32, 112, 114,
				    111, 115, 112, 101, 114, 46));

		$expected = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";

        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);

        $obj = new JweSerializer(JoseActionType::SERIALIZE, $joseHeader, $src, $key);
        $obj->setUserEncryptionKey($cek, $iv);

        $actual = $obj->compactSeriaization();

        var_dump($actual);

        $this->assertEquals($expected, $actual);
    }

    public function testSerialize1()
    {
        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);
        $joseHeader->setKid('test');

        $key = '1234567890123456';
        $src = 'fruit';

        $obj = new JweSerializer(JoseActionType::SERIALIZE, $joseHeader, $src, $key);
        $actual = $obj->compactSeriaization();

        echo $actual;
    }

    public function testSerialize2()
    {
        $key = '1234567890123456';
        $enc = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoic2FtcGxlIn0.lc6vneeyjCkrqYglDjpko_o3xhqOVCXzhiX18XBR81vVJQdbTmiZsQ.RhhznCpTdOg1UHHK8kjMEQ.pQwfc-MMU7BIgrFSON5jQw.ath4c3U5lADxwCMM8WLdgQ";

        $obj = new JweSerializer(JoseActionType::DESERAILIZE, $enc, $key);
        $actual = $obj->compactSeriaization();

        var_dump($actual);
    }
}
