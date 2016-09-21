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

/**
 * Content encryption key를 생성하는 클래스
 *
 * @package syruppay\jose\jwa\enc
 */
class ContentEncryptKeyGenerator
{
    /**
     * @var int content encryption key 길이
     */
    private $keyLength;

    /**
     * @var string 생성한 content encryption key
     */
    private $cek;

    public function __construct($keyLength)
    {
        $this->keyLength = $keyLength;
    }

    /**
     * 사용자 cek를 셋팅한다. 테스트 용도로 사용해야만 한다.
     * @param $cek
     */
    public function setUserEncryptionKey($cek)
    {
        $this->cek = $cek;
    }

    /**
     * cek를 생성한다.
     *
     * @return String
     */
    public function generateRandomKey()
    {
        if (is_null($this->cek))
        {
            $this->cek = crypt_random_string($this->keyLength);
        }

        return $this->cek;
    }
}
