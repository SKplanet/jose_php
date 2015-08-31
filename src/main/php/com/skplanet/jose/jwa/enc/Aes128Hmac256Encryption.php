<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 12:11
 */

namespace com\skplanet\jose\jwa\enc;

use com\skplanet\jose\util\Base64UrlSafeEncoder;
use com\skplanet\jose\util\ByteUtils;


/**
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
 *
 * Class Aes128Hmac256Encryption
 * @package com\skplanet\jose\jwa\enc
 */
class Aes128Hmac256Encryption extends ContentEncryption
{
    public function __construct()
    {
        parent::__construct(32, 16);
    }

    public function encryptAndSign($cek, $iv, $payload, $aad)
    {
        $iv = !is_null($iv)?$iv:$this->generateRandomIv();
        $hmacKey = substr($cek, 0, 16);
        $encKey = substr($cek, 16, 16);

        $cipherText = $this->encryption($encKey, $iv, $payload);
        $at = $this->sign($hmacKey, $iv, $cipherText, $aad);

        return new JweEncResult($cipherText, $at, $iv);
    }

    public function verifyAndDecrypt($cek, $iv, $cipherText, $aad, $expected)
    {
        $hmacKey = substr($cek, 0, 16);
        $encKey = substr($cek, 16, 16);

        $this->verifyAuthenticationTag($hmacKey, $iv, $cipherText, $aad, $expected);
        return $this->decryption($encKey, $iv, $cipherText);
    }

    private function decryption($key, $iv, $cipherText)
    {
        $cipher = new \Crypt_AES(CRYPT_MODE_CBC);
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->enablePadding();

        $payload = $cipher->decrypt($cipherText);

        return $payload;
    }

    private function verifyAuthenticationTag($hmacKey, $iv, $cipherText, $aad, $expected)
    {
        $actual = Base64UrlSafeEncoder::encode($this->sign($hmacKey, $iv, $cipherText, $aad));

        if ($actual!= $expected)
            throw new InvalidAuthenticationTagException('not match : '.$actual);
    }

    private function encryption($key, $iv, $src)
    {
        $cipher = new \Crypt_AES(CRYPT_MODE_CBC);
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->enablePadding();

        return $cipher->encrypt($src);
    }

    private function sign($key, $iv, $cipherText, $aad)
    {
        $al = $this->getAl($aad);
        $at = substr(hash_hmac('sha256', implode('', array($aad, $iv, $cipherText, $al)), $key, true), 0, 16);

        return $at;
    }

    private function getAl($aad)
    {
        $aadLen = strlen($aad)*8;
        return ByteUtils::convert2UnsignedLongBE($aadLen);
    }
}
