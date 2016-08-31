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

namespace com\skplanet\jose\jwa\alg;


use com\skplanet\jose\exception\InvalidSignatureException;

/**
 * HmacSha256 처리를 하는 클래스
 *
 * @package com\skplanet\jose\jwa\alg
 */
class HmacSha256Signature extends Signature
{

    public function sign($src, $key)
    {
        $this->raw = hash_hmac('sha256', $src, $key, true);
    }

    public function verify($src, $expected, $key)
    {
        $this->sign($src, $key);
        $actual = $this->serialize();

        if ($actual != $expected)
        {
            throw new InvalidSignatureException('invalid signature');
        }
    }
}
