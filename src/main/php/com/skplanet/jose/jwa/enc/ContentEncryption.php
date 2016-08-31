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

namespace com\skplanet\jose\jwa\enc;

/**
 * Content encryption 처리 super 클래스
 *
 * @package com\skplanet\jose\jwa\enc
 */
class ContentEncryption
{
    /**
     * @var int content encryption key 길이
     */
    protected $keyLength = 0;

    /**
     * @var int content encryption iv key 길이
     */
    protected $ivLength = 0;

    public function __construct($keyLength, $ivLength)
    {
        $this->keyLength = $keyLength;
        $this->ivLength = $ivLength;
        return $this;
    }

    /**
     * iv 길이 반환한다.
     *
     * @return int
     */
    private function getIvLength()
    {
        return $this->ivLength;
    }

    /**
     * iv를 생성한다.
     *
     * @return String
     */
    public function generateRandomIv()
    {
        return crypt_random_string($this->getIvLength());
    }

    /**
     * content encryption key 생성 클래스를 반환한다.
     *
     * @return ContentEncryptKeyGenerator
     */
    public function getContentEncryptionKeyGenerator()
    {
        return new ContentEncryptKeyGenerator($this->keyLength);
    }
}
