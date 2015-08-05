<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 3:28
 */

namespace com\skplanet\jose\jwa\enc;


use com\skplanet\jose\util\Base64UrlSafeEncoder;

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
 * Class ContentEncryption
 * @package com\skplanet\jose\jwa\enc
 */
class ContentEncryption
{
    protected $raw;
    protected $keyLength = 0;
    protected $ivLength = 0;

    public function __construct($keyLength, $ivLength)
    {
        $this->keyLength = $keyLength;
        $this->ivLength = $ivLength;
        return $this;
    }

    public function getKeyLength()
    {
        return $this->keyLength;
    }

    public function getIvLength()
    {
        return $this->ivLength;
    }

    public function generateRandomKey($size)
    {
        return crypt_random_string($size);
    }

    public function getRaw()
    {
        return $this->raw;
    }

    public function serialize()
    {
        if (is_null($this->raw))
        {
            throw new \InvalidArgumentException("encrypt/decrypt raw is null");
        }

        return Base64UrlSafeEncoder::encode($this->raw);
    }
}
