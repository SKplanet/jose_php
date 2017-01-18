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
 * JWA 알고리즘 상수
 *
 * @package syruppay\jose
 */
define('JWA_A128KW',            'A128KW');
define('JWA_A256KW',            'A256KW');
define('JWA_A128CBC_HS256',     'A128CBC-HS256');
define('JWA_HS256',             'HS256');

/**
 * JOSE 처리 타입 상수
 *
 * @package syruppay\jose
 */
define('JOSE_ACTION_SERIALIZE', 'SERIALIZE');
define('JOSE_ACTION_DESERIALIZE', 'DESERIALIZE');

/**
 * JOSE에서 지원하는 header key 정의 (일부만 지원)
 *
 * @package syruppay\jose
 */

define('JOSE_HEADER_ALG', 'alg');
define('JOSE_HEADER_ENG', 'enc');
define('JOSE_HEADER_KID', 'kid');
define('JOSE_HEADER_TYP', 'typ');

/**
 * JOSE 기능 타입 상수 정의
 *
 * @package syruppay\jose
 */
define('JOSE_JWS', 1);
define('JOSE_JWE', 2);

/**
 * JOSE encyrption, sign 처리 방식에 대한 상수 정의
 *
 * @package syruppay\jose
 */

define('JOSE_COMPACT_SERIALIZATION', 1);
define('JOSE_JSON_SERIALIZATION', 2);