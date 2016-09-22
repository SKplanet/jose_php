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

/**
 * JOSE 구현 기능을 정의한다.
 *
 * @package syruppay\jose
 */
interface JoseAction
{
    /**
     * JOSE 규격의 compact serialize를 처리한다.
     *
     * @return string JOSE compact serialize value
     * @throws InvalidArgumentException 규격과 다른 암호화/서명 키 길이
     */
    function compactSerialization();

    /**
     * JOSE 규격의 compact deserialize를 처리한다.
     *
     * @return string payload (JSON)
     * @throws InvalidAuthenticationTagException JWE authentication tag verify 오류
     * @throws InvalidSignatureException JWS signature verify 오류
     */
    function compactDeserialization();

    /**
     * JOSE의 Header class를 반환한다.
     *
     * @return JoseHeader
     */
    function getJoseHeader();
}
