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

/**
 * JWE처리에 사용하는 Content Encryption Key 관리 클래스
 *
 * @package syruppay\jose\jwa\alg
 */
class syruppay_jose_jwa_alg_JweAlgResult
{
    /**
     * @var string random하게 생성된 content encryption key
     */
    private $cek;

    /**
     * @var string wrapped content encryption key
     */
    private $encryptedCek;

    public function __construct($cek, $encryptedCek)
    {
        $this->cek = $cek;
        $this->encryptedCek = $encryptedCek;
    }

    /**
     * wrapped 된 content encryption key를 반환한다.
     *
     * @return string
     */
    public function getEncryptedCek()
    {
        return $this->encryptedCek;
    }

    /**
     * content encryption key를 반환한다.
     * @return string
     */
    public function getCek()
    {
        return $this->cek;
    }
}
