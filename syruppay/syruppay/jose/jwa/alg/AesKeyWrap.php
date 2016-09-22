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

namespace syruppay\jose\jwa\alg;
use syruppay\jose\jwa\enc\ContentEncryptKeyGenerator;

/**
 * AesKeyWrap 처리하는 추상 클래스
 *
 * @package syruppay\jose\jwa\alg
 */
abstract class AesKeyWrap
{
    /**
     * @var int Wrap/UnWrap 키 길이
     */
    private $keyLength;

    public function __construct($keyLength)
    {
        $this->keyLength = $keyLength;
    }

    /**
     * 입력받은 키가 유효한 키길이인지 확인한다.
     * 만약 키 길이가 올바르지 않으면 exception을 발생한다.
     *
     * @param $key string
     * @throws InvalidArgumentException 키 길이가 유효하지 않으면 발생
     */
    private function isValidKeyLength($key)
    {
        if ($this->keyLength != strlen($key))
        {
            throw new \InvalidArgumentException('JWE key must be '.$this->keyLength.' bytes. Yours key '.strlen($key).' bytes.');
        }
    }

    /**
     * key wrap 처리를 한다.
     *
     * @param $key string key to wrap
     * @param $cekGenerator ContentEncryptKeyGenerator content encryption key 생성 클래스
     * @return JweAlgResult
     */
    public function encryption($key, $cekGenerator)
    {
        $this->isValidKeyLength($key);
        $cek = $cekGenerator->generateRandomKey();
        $wrapCek = $this->wrap($key, $cek);

        return new JweAlgResult($cek, $wrapCek);
    }

    /**
     * key unwarp 처리를 한다.
     *
     * @param $key string key to unwrap
     * @param $wrapCek string wrapped key
     * @return string content encryption key
     */
    public function decryption($key, $wrapCek)
    {
        $this->isValidKeyLength($key);
        $cek = $this->unwrap($key, $wrapCek);

        return $cek;
    }

    /**
     * key unwrap 처리를 한다.
     *
     * @param $key string key encryption key
     * @param $src string content encryption key to unwrap
     * @return string
     */
    abstract function unwrap($key, $src);

    /**
     * key wrap 처리를 한다.
     *
     * @param $key string key encryption key
     * @param $src string content encryption key
     * @return string
     */
    abstract public function wrap($key, $src);
}
