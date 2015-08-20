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
    protected $raw;   //hex

    public function __construct($keylength)
    {
        $this->keyLength = $keylength;
    }

    public function encryption($key, $src)
    {
        $this->isValidKeyLength($key);
        $this->wrap($key, $src);
    }

    abstract public function wrap($key, $src);

    public function decryption($key, $src)
    {
        $this->isValidKeyLength($key);
        $this->unwrap($key, $src);
    }

    abstract function unwrap($key, $src);

    private function isValidKeyLength($key)
    {
        if ($this->keyLength != strlen($key))
        {
//            throw new \InvalidArgumentException('JWE key must be '.$this->keyLength.' bytes');
        }
    }

    public function serialize()
    {
        if (!is_null($this->raw))
            return Base64UrlSafeEncoder::encode($this->raw);
        else
            return null;
    }

    public function deserialize($src)
    {
        if (!is_null($src))
            return Base64UrlSafeEncoder::decode($src);
        else
            return null;
    }

    public function getRaw()
    {
        return $this->raw;
    }
}
