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
 * JWE처리에 사용하는 암호화된 payload 관리 클래스
 *
 * @package com\skplanet\jose\jwa\enc
 */
class JweEncResult
{
    /**
     * @var string 암호화된 paylod
     */
    private $cipherText;

    /**
     * @var string
     */
    private $at;

    /**
     * @var string
     */
    private $iv;

    public function __construct($cipherText, $at, $iv)
    {
        $this->cipherText = $cipherText;
        $this->at = $at;
        $this->iv = $iv;
    }

    /**
     * 암호화된 payload를 반환한다.
     *
     * @return string
     */
    public function getCipherText()
    {
        return $this->cipherText;
    }

    /**
     * at를 반환한다.
     *
     * @return string
     */
    public function getAt()
    {
        return $this->at;
    }

    /**
     * iv를 반환한다.
     *
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }
}
