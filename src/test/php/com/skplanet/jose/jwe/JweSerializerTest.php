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

        $aesKeyWrap = new Aes128KeyWrap(16);
        $aesKeyWrap->encryption($key, $cek);
        $actual = $aesKeyWrap->serialize();

        $this->assertEquals($expected, $actual);
    }

    public function testIv()
    {
        $jweEnc = JwaFactory::getJweEncryptionAlgorithm(Jwa::A128CBC_HS256);
        $jweSerializer = new JweSerializer(JoseActionType::SERAILIZE, null, null, null);

        $iv = $jweSerializer->getIv($jweEnc);
        $cek = $jweSerializer->getCek($jweEnc);

        $this->assertEquals(16, strlen($iv));
        $this->assertEquals(32, strlen($cek));
    }

    public function testCekEncrytpion()
    {
        $expected = 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY';

        $cek = ByteUtils::convertHalfWordArrayToBin(
                array(76, 105, 118, 101, 32, 108, 111, 110,
				    103, 32, 97, 110, 100, 32, 112, 114,
				    111, 115, 112, 101, 114, 46));

		$key = ByteUtils::convertHalfWordArrayToBin(
                array(4, 211, 31, 197, 84, 157, 252, 254,
				    11, 100, 157, 250, 63, 170, 106, 206,
				    107, 124, 212, 45, 111, 107, 9, 219,
				    200, 177, 0, 240, 143, 156, 44, 207));

		$iv = ByteUtils::convertHalfWordArrayToBin(
                array(3, 22, 60, 12, 43, 67, 104, 105,
				    108, 108, 105, 99, 111, 116, 104, 101));

        $jweEnc = JwaFactory::getJweEncryptionAlgorithm(Jwa::A128CBC_HS256);
        $jweEnc->encryption($cek, $key, $iv);
        $actual = $jweEnc->serialize();

        $this->assertEquals($expected, $actual);
    }

    public function testGetAl()
    {
        //0000000000000198
        $expected = ByteUtils::bin2hex(ByteUtils::convertHalfWordArrayToBin(
            array(0, 0, 0, 0, 0, 0, 1, 152)));

        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);

        $jweSerializer = new JweSerializer(JoseActionType::SERAILIZE, $joseHeader, null, null);
        $actual = $jweSerializer->getAl();

        $this->assertEquals($expected, ByteUtils::bin2hex($actual));
    }

    public function testHmac()
    {
        $aad = ByteUtils::convertHalfWordArrayToBin(
                array(101, 121, 74, 104, 98, 71, 99, 105,
				    79, 105, 74, 66, 77, 84, 73, 52, 83,
				    49, 99, 105, 76, 67, 74, 108, 98, 109,
				    77, 105, 79, 105, 74, 66, 77, 84, 73,
				    52, 81, 48, 74, 68, 76, 85, 104, 84,
				    77, 106, 85, 50, 73, 110, 48));

		$iv = ByteUtils::convertHalfWordArrayToBin(
                array(3, 22, 60, 12, 43, 67, 104, 105,
				    108, 108, 105, 99, 111, 116, 104, 101));

		$cipherText = ByteUtils::convertHalfWordArrayToBin(
                array(40, 57, 83, 181, 119, 33, 133,
				    148, 198, 185, 243, 24, 152, 230, 6, 75,
				    129, 223, 127, 19, 210, 82, 183, 230,
				    168, 33, 215, 104, 143, 112, 56, 102));

		$al = ByteUtils::convertHalfWordArrayToBin(array(0, 0, 0, 0, 0, 0, 1, 152));

		$expected = ByteUtils::bin2hex(ByteUtils::convertHalfWordArrayToBin(
                array(101, 121, 74, 104, 98, 71, 99, 105,
				    79, 105, 74, 66, 77, 84, 73, 52, 83,
				    49, 99, 105, 76, 67, 74, 108, 98, 109,
				    77, 105, 79, 105, 74, 66, 77, 84, 73,
				    52, 81, 48, 74, 68, 76, 85, 104, 84,
				    77, 106, 85, 50, 73, 110, 48, 3, 22,
				    60, 12, 43, 67, 104, 105, 108, 108, 105,
				    99, 111, 116, 104, 101, 40, 57, 83, 181,
				    119, 33, 133, 148, 198, 185, 243, 24,
				    152, 230, 6, 75, 129, 223, 127, 19, 210,
				    82, 183, 230, 168, 33, 215, 104, 143,
				    112, 56, 102, 0, 0, 0, 0, 0, 0,
				    1, 152)));

        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);

        $jweSerializer = new JweSerializer(JoseActionType::SERAILIZE, $joseHeader, null, null);
        $actual = $jweSerializer->getHmac($aad, $iv, $cipherText, $al);

        $this->assertEquals($expected, ByteUtils::bin2hex($actual));
    }

    public function testAt()
    {
        $expected = 'U0m_YmjN04DJvceFICbCVQ';

        $aad = ByteUtils::convertHalfWordArrayToBin(
            array(101, 121, 74, 104, 98, 71, 99, 105,
                79, 105, 74, 66, 77, 84, 73, 52, 83,
                49, 99, 105, 76, 67, 74, 108, 98, 109,
                77, 105, 79, 105, 74, 66, 77, 84, 73,
                52, 81, 48, 74, 68, 76, 85, 104, 84,
                77, 106, 85, 50, 73, 110, 48));

        $iv = ByteUtils::convertHalfWordArrayToBin(
            array(3, 22, 60, 12, 43, 67, 104, 105,
                108, 108, 105, 99, 111, 116, 104, 101));

        $cipherText = ByteUtils::convertHalfWordArrayToBin(
            array(40, 57, 83, 181, 119, 33, 133,
                148, 198, 185, 243, 24, 152, 230, 6, 75,
                129, 223, 127, 19, 210, 82, 183, 230,
                168, 33, 215, 104, 143, 112, 56, 102));

        $al = ByteUtils::convertHalfWordArrayToBin(array(0, 0, 0, 0, 0, 0, 1, 152));

		$cek = ByteUtils::convertHalfWordArrayToBin(
                array(4, 211, 31, 197, 84, 157, 252, 254,
                    11, 100, 157, 250, 63, 170, 106, 206,
                    107, 124, 212, 45, 111, 107, 9, 219,
                    200, 177, 0, 240, 143, 156, 44, 207));

        $joseHeader = new JoseHeader();
        $joseHeader->setAlg(Jwa::A128KW);
        $joseHeader->setEnc(Jwa::A128CBC_HS256);

        $jweSerializer = new JweSerializer(JoseActionType::SERAILIZE, $joseHeader, null, null);
        $jweSerializer->setCek($cek);
        $at = $jweSerializer->getAt($aad, $iv, $cipherText, $al);
        $actual = Base64UrlSafeEncoder::encode($at);

        $this->assertEquals($expected, $actual);
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

        $obj = new JweSerializer(JoseActionType::SERAILIZE, $joseHeader, $src, $key);
        $obj->setCek($cek);
        $obj->setIv($iv);

        $actual = $obj->compactSeriaization();

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

        $obj = new JweSerializer(JoseActionType::SERAILIZE, $joseHeader, $src, $key);
        $actual = $obj->compactSeriaization();

        echo $actual;
    }
}
