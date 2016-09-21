<?php
/*
 * LICENSE : Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace syruppay\jose\jwa\enc;

use syruppay\jose\util\Base64UrlSafeEncoder;
use syruppay\jose\util\ByteUtils;

/**
 * A128CBC-HS256 알고리즘을 처리하는 클래스
 *
 * @package syruppay\jose\jwa\enc
 */
class Aes128Hmac256Encryption extends ContentEncryption
{
    public function __construct()
    {
        parent::__construct(32, 16);
    }

    /**
     * encryption 및 signature를 생성하여 결과를 반환한다.
     *
     * @param $cek string
     * @param $iv string
     * @param $payload string
     * @param $aad string
     * @return JweEncResult
     */
    public function encryptAndSign($cek, $iv, $payload, $aad)
    {
        $iv = !is_null($iv)?$iv:$this->generateRandomIv();
        $hmacKey = substr($cek, 0, 16);
        $encKey = substr($cek, 16, 16);

        $cipherText = $this->encryption($encKey, $iv, $payload);
        $at = $this->sign($hmacKey, $iv, $cipherText, $aad);

        return new JweEncResult($cipherText, $at, $iv);
    }

    /**
     * signature 유효성을 확인 한 후 decryption 처리후 payload를 반환한다.
     * 만약 signature가 유효하지 않는다면 InvalidAuthenticationTagException를 발생한다.
     *      *
     * @param $cek string
     * @param $iv string
     * @param $cipherText string
     * @param $aad string
     * @param $expected string signature 기대값
     * @return String
     * @throws InvalidAuthenticationTagException
     */
    public function verifyAndDecrypt($cek, $iv, $cipherText, $aad, $expected)
    {
        $hmacKey = substr($cek, 0, 16);
        $encKey = substr($cek, 16, 16);

        $this->verifyAuthenticationTag($hmacKey, $iv, $cipherText, $aad, $expected);
        return $this->decryption($encKey, $iv, $cipherText);
    }

    /**
     * 암호화된 payload를 복호화한다.
     *
     * @param $key
     * @param $iv
     * @param $cipherText
     * @return String
     */
    private function decryption($key, $iv, $cipherText)
    {
        $cipher = new \Crypt_AES(CRYPT_MODE_CBC);
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->enablePadding();

        $payload = $cipher->decrypt($cipherText);

        return $payload;
    }

    /**
     * authentication tag 검증을 수행한다. 만약 유효하지 않는다면 exception 발생한다.
     *
     * @param $hmacKey
     * @param $iv
     * @param $cipherText
     * @param $aad
     * @param $expected
     * @throws InvalidAuthenticationTagException
     */
    private function verifyAuthenticationTag($hmacKey, $iv, $cipherText, $aad, $expected)
    {
        $actual = Base64UrlSafeEncoder::encode($this->sign($hmacKey, $iv, $cipherText, $aad));

        if ($actual!= $expected)
            throw new InvalidAuthenticationTagException('not match : '.$actual);
    }

    /**
     * payload를 content encryption key로 암호화를 한다.
     *
     * @param $key
     * @param $iv
     * @param $src
     * @return String
     */
    private function encryption($key, $iv, $src)
    {
        $cipher = new \Crypt_AES(CRYPT_MODE_CBC);
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->enablePadding();

        return $cipher->encrypt($src);
    }

    /**
     * HmacSha256 sign 값 생성한다.
     *
     * @param $key
     * @param $iv
     * @param $cipherText
     * @param $aad
     * @return string
     */
    private function sign($key, $iv, $cipherText, $aad)
    {
        $al = $this->getAl($aad);
        $at = substr(hash_hmac('sha256', implode('', array($aad, $iv, $cipherText, $al)), $key, true), 0, 16);

        return $at;
    }

    /**
     * aad 값에서 al 값을 추출한다.
     * @param $aad
     * @return string
     */
    private function getAl($aad)
    {
        $aadLen = strlen($aad)*8;
        return ByteUtils::convert2UnsignedLongBE($aadLen);
    }
}
