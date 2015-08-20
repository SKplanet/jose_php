<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 12:01
 */

namespace com\skplanet\jose\jwa;

use com\skplanet\jose\jwa\alg\Aes128KeyWrap;
use com\skplanet\jose\jwa\alg\Aes256KeyWrap;
use com\skplanet\jose\jwa\alg\HmacSha256Signature;
use com\skplanet\jose\jwa\enc\Aes128Hmac256Encryption;

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
 * Class JwaFactory
 * @package com\skplanet\jose\jwa
 */
class JwaFactory
{
    public static function getJweAlgorithm($alg)
    {
        if ($alg == Jwa::A128KW)
        {
            return new Aes128KeyWrap(16);
        }
        else if ($alg == Jwa::A256KW)
        {
            return new Aes256KeyWrap(32);
        }
    }

    public static function getJweEncryptionAlgorithm($enc)
    {
        if ($enc == Jwa::A128CBC_HS256)
        {
            return new Aes128Hmac256Encryption();
        }
    }

    public static function getJwsAlgorithm($alg)
    {
        if ($alg == Jwa::HS256)
        {
            return new HmacSha256Signature(32);
        }
    }
}
