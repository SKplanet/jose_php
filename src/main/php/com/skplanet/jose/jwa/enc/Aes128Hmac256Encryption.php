<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 12:11
 */

namespace com\skplanet\jose\jwa\enc;

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

    /**
     * @param $payload plain
     * @param $key
     * @param $iv
     * @return String encryption content (not base64url encoding)
     */
    public function encryption($payload, $key, $iv)
    {
        $secret = substr($key, 16, 16);

        $cipher = new \Crypt_AES(CRYPT_MODE_CBC);
        $cipher->setKey($secret);
        $cipher->setIV($iv);
        $cipher->enablePadding();

        $this->raw = $cipher->encrypt($payload);

        return $this;
    }

    /**
     * @param $cipherText encrypted content (not base64url encoding)
     * @param $key
     * @param $iv
     * @return String decrypted content
     */
    public function decryption($cipherText, $key, $iv)
    {
        $secret = substr($key, 16, 16);

        $cipher = new \Crypt_AES(CRYPT_MODE_CBC);
        $cipher->setKey($secret);
        $cipher->setIV($iv);
        $cipher->enablePadding();

        $this->raw = $cipher->decrypt($cipherText);

        return $this;
    }
}
