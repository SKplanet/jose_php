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


use syruppay\jose\util\Base64UrlSafeEncoder;

/**
 * signature를 생성하는 추상 클래스
 *
 * @package syruppay\jose\jwa\alg
 */
abstract class Signature
{
    /**
     * @var int sign 키길이
     */
    private $keyLength;

    /**
     * @var string sign된 payload
     */
    protected $raw;

    public function __construct($keyLength)
    {
        $this->keyLength = $keyLength;
    }


    /**
     * 입력받은 키가 유효한 키 길이인지 확인한다.
     * 만약 키 길이가 올바르지 않으면 exception을 발생한다.
     *
     * @param $key string
     * @throws InvalidArgumentException 키 길이가 유효하지 않으면 발생
     */
    protected function isValidKeyLength($key)
    {
        if (strlen($key) != $this->keyLength)
        {
            throw new \InvalidArgumentException('JWS hash key must be '.$this->keyLength.' bytes');
        }
    }

    /**
     * sign 된 payload를 base64url 인코딩하여 반환한다.
     * 만약 payload가 null인 경우 null을 반환한다.
     *
     * @return null|string
     */
    public function serialize()
    {
        if (!is_null($this->raw))
            return Base64UrlSafeEncoder::encode($this->raw);
        else
            return null;
    }

    /**
     * 입력받은 payload를 입력받은 key로 sign 한다.
     *
     * @param $src string payload
     * @param $key string key to sign
     * @return string
     */
    abstract public function sign($src, $key);

    /**
     * 입력받은 payload와 key로 생성한 sing 값이 기대값과 동일한지 검증 후
     * 동일하면 payload를 반환하고 동일하지 않다면 exception을 발생한다.
     *
     * @param $src string payload
     * @param $expected string 기대값
     * @param $key string key to sing
     * @return string
     * @throws InvalidSignatureException sign 값과 기대값이 동일하지 않으면 발생
     */
    abstract public function verify($src, $expected, $key);
}
