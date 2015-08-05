<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오후 12:46
 */

namespace com\skplanet\jose;


use com\skplanet\jose\exception\UnSupportedJoseAlgorithmException;
use com\skplanet\jose\jwa\Jwa;
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
 * Class JoseHeader
 * @package com\skplanet\jose
 */
class JoseHeader
{
    private $supported = array();

    private $header = array();

    public function __construct()
    {
        $this->supported = array(
            'ALG' => array(
                Jwa::A128KW => true,
                Jwa::HS256 => true),
            'ENC' => array(
                Jwa::A128CBC_HS256 => true)
        );
    }

    public function setAlg($alg)
    {
        $this->isSupportAlg($alg);
        $this->header[JoseHeaderSpec::ALG] = $alg;
        return $this;
    }

    public function getAlg()
    {
        return $this->header[JoseHeaderSpec::ALG];
    }

    public function setEnc($enc)
    {
        $this->isSupportEnc($enc);
        $this->header[JoseHeaderSpec::ENC] = $enc;
        return $this;
    }

    public function getEnc()
    {
        return $this->header[JoseHeaderSpec::ENC];
    }

    public function setKid($kid)
    {
        $this->header[JoseHeaderSpec::KID] = $kid;
        return $this;
    }

    public function getKid()
    {
        return $this->header[JoseHeaderSpec::KID];
    }

    public function setHeader($key, $value)
    {
        $this->header[$key] = $value;
        return $this;
    }

    public function getHeader($key)
    {
        return $this->header[$key];
    }

    public function __toString()
    {
        return json_encode($this->header);
    }

    public function serialize()
    {
        return Base64UrlSafeEncoder::encode($this->__toString());
    }

    public function deserialize($src)
    {
        $this->header = json_decode(Base64UrlSafeEncoder::decode($src), true);
    }

    private function isSupportAlg($alg)
    {
        if (!array_key_exists($alg, $this->supported['ALG']) || !$this->supported['ALG'][$alg])
        {
            throw new UnSupportedJoseAlgorithmException("unknown header 'alg' value : ".$alg);
        }
    }

    private function isSupportEnc($enc)
    {
        if (!array_key_exists($enc, $this->supported['ENC']) || !$this->supported['ENC'][$enc])
        {
            throw new UnSupportedJoseAlgorithmException("unknown header 'enc' value : ".$enc);
        }
    }
}
