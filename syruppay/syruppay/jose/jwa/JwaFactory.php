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
 * 입력받은 파라미터에 따라 암호화/서명 클래스를 반환하는 factory class
 *
 * @package syruppay\jose\jwa
 */
class syruppay_jose_jwa_JwaFactory
{
    /**
     * 입력받은 알고리즘에 따라 JWE key encryption 클래스를 반환한다.
     *
     * @param $alg Jwa
     * @return Aes128KeyWrap|Aes256KeyWrap
     */
    public static function getJweAlgorithm($alg)
    {
        if ($alg == JWA_A128KW)
        {
            return new syruppay_jose_jwa_alg_Aes128KeyWrap(16);
        }
        else if ($alg == JWA_A256KW)
        {
            return new syruppay_jose_jwa_alg_Aes256KeyWrap(32);
        }
    }

    /**
     * 입력받은 알고리즘에 따라 JWE content encryption, sign 클래스를 반환한다.
     *
     * @param $enc Jwa
     * @return Aes128Hmac256Encryption
     */
    public static function getJweEncryptionAlgorithm($enc)
    {
        if ($enc == JWA_A128CBC_HS256)
        {
            return new syruppay_jose_jwa_enc_Aes128Hmac256Encryption();
        }
    }

    /**
     * 입력받은 알고리즘에 따라 JWS signature 클래스를 반환한다.
     *
     * @param $alg Jwa
     * @return HmacSha256Signature
     */
    public static function getJwsAlgorithm($alg)
    {
        if ($alg == JWA_HS256)
        {
            return new syruppay_jose_jwa_alg_HmacSha256Signature(32);
        }
    }
}
