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

namespace syruppay\jose;
use syruppay\jose\jwa\Jwa;

/**
 * 지원하는 JOSE alg 알고리즘 여부를 판단하는 class
 *
 * @package com\skplanet\jose
 */
class JoseSupportAlgorithm
{
    /**
     * @var array JWE: A128KW, A256KW 지원
     */
    private static $jweSupportAlg = array(
        Jwa::A128KW,
        Jwa::A256KW
    );

    /**
     * @var array JWS: HS256 지원
     */
    private static $jwsSupportAlg = array(
        Jwa::HS256
    );

    /**
     * 입력한 alg가 지원하는 알고리즘인지 확인을 한다.
     *
     * @param $alg string
     * @return bool
     */
    public static function isSupported($alg)
    {
        return self::isJWESupported($alg) or self::isJWSSupported($alg);
    }

    /**
     * 입력한 alg가 JWE 지원하는 알고리즘인지 확인을 한다.
     *
     * @param $alg string
     * @return bool
     */
    public static function isJWESupported($alg)
    {
        return in_array($alg, self::$jweSupportAlg);
    }

    /**
     * 입력한 alg가 JWS 지원하는 알고리즘인지 확인을 한다.
     *
     * @param $alg string
     * @return bool
     */
    public static function isJWSSupported($alg)
    {
        return in_array($alg, self::$jwsSupportAlg);
    }
}
