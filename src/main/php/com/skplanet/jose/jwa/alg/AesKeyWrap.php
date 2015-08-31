<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 12:04
 */

namespace com\skplanet\jose\jwa\alg;


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
 * Class AesKeyWrap
 * @package com\skplanet\jose\jwa\alg
 */
abstract class AesKeyWrap
{
    private $keyLength;

    public function __construct($keyLength)
    {
        $this->keyLength = $keyLength;
    }

    private function isValidKeyLength($key)
    {
        if ($this->keyLength != strlen($key))
        {
            throw new \InvalidArgumentException('JWE key must be '.$this->keyLength.' bytes. Yours key '.strlen($key).' bytes.');
        }
    }

    public function encryption($key, $cekGenerator)
    {
        $this->isValidKeyLength($key);
        $cek = $cekGenerator->generateRandomKey();
        $wrapCek = $this->wrap($key, $cek);

        return new JweAlgResult($cek, $wrapCek);
    }

    public function decryption($key, $wrapCek)
    {
        $this->isValidKeyLength($key);
        $cek = $this->unwrap($key, $wrapCek);

        return $cek;
    }

    abstract function unwrap($key, $src);
    abstract public function wrap($key, $src);
}
