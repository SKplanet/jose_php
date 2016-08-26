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

namespace com\skplanet\jose;

use com\skplanet\jose\exception\UnSupportedJoseAlgorithmException;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\util\Base64UrlSafeEncoder;

/**
 * JOSE header 관리 class
 *
 * @package com\skplanet\jose
 */
class JoseHeader
{
    private $header = array();

    /**
     * JoseHeaderSpec에서 정의한 상수를 key로 JOSE header를 생성한다.
     *
     * @param array
     */
    public function __construct()
    {
        $argNum = func_num_args();
        $arg = func_get_args();
        if ($argNum == 1 and is_array($arg[0]))
        {
            foreach($arg[0] as $key => $value)
            {
                $this->setHeader($key, $value);
            }
        }
        else if ($argNum != 0)
        {
            throw new \InvalidArgumentException('Usage : new JoseHeader(array(JoseHeaderSpec => $value)');
        }
    }

    /**
     * JOSE 규격 alg를 셋팅한다.
     *
     * @param $alg string
     * @return $this
     * @throws UnSupportedJoseAlgorithmException 지원하지 않는 알고리즘인 경우 exception 발생
     */
    public function setAlg($alg)
    {
        if (!JoseSupportAlgorithm::isSupported($alg))
        {
            throw new UnSupportedJoseAlgorithmException("unknown header 'alg' value : ".$alg);
        }

        $this->header[JoseHeaderSpec::ALG] = $alg;
        return $this;
    }

    /**
     * header에 셋팅된 alg value를 반환한다.
     *
     * @return string
     */
    public function getAlg()
    {
        return $this->header[JoseHeaderSpec::ALG];
    }

    /**
     * JOSE 규격 enc를 세팅한다.
     *
     * @param $enc string
     * @return $this
     * @throws UnSupportedJoseAlgorithmException 지원하지 않는 알고리즘인 경우 exception 발생
     */
    public function setEnc($enc)
    {
        if (!JoseSupportEncryption::isSupported($enc))
        {
            throw new UnSupportedJoseAlgorithmException("unknown header 'enc' value : ".$enc);
        }

        $this->header[JoseHeaderSpec::ENC] = $enc;
        return $this;
    }

    /**
     * header에 셋팅된 enc value를 반환한다.
     *
     * @return mixed
     */
    public function getEnc()
    {
        return $this->header[JoseHeaderSpec::ENC];
    }

    /**
     * JOSE 규격 kid를 세팅한다.
     *
     * @param $kid string
     * @return $this
     */
    public function setKid($kid)
    {
        $this->header[JoseHeaderSpec::KID] = $kid;
        return $this;
    }

    /**
     * header에 셋팅된 kid value를 반환한다.
     *
     * @return mixed
     */
    public function getKid()
    {
        return $this->header[JoseHeaderSpec::KID];
    }

    /**
     * key, value로 header를 세팅한다.
     *
     * @param $key JoseHeaderSpec
     * @param $value
     * @return $this
     */
    public function setHeader($key, $value)
    {
        $this->header[$key] = $value;
        return $this;
    }

    /**
     * headere에 key로 셋팅된 value를 반환한다.
     *
     * @param $key
     * @return string
     */
    public function getHeader($key)
    {
        return $this->header[$key];
    }

    /**
     * header를 JSON으로 변환하여 반환하다.
     *
     * @return string JSON
     */
    private function toJson()
    {
        return json_encode($this->header);
    }

    /**
     * JSON으로 변환된 header를 base64url로 변환하여 반환한다.
     *
     * @return string
     */
    public function serialize()
    {
        return Base64UrlSafeEncoder::encode($this->toJson());
    }

    /**
     * 입력한 JWE, JWS 값 중에서 header 부분을 추출하여 header로 변환한다.
     *
     * @param $src JWE or JWS value
     */
    public function deserialize($src)
    {
        list($headerToken, $rest) = array_pad(explode(".", $src, 2), 2, null);
        $this->header = json_decode(Base64UrlSafeEncoder::decode($headerToken), true);
    }

    /**
     * alg에 따른 JOSE type를 반환한다.
     *
     * @return JoseMethod
     * @throws UnSupportedJoseAlgorithmException 지원하지 않는 alg면 exception 발생
     */
    public function getJoseMethod()
    {
        if (JoseSupportAlgorithm::isJWESupported($this->getAlg()))
        {
            return JoseMethod::JWE;
        }
        else if (JoseSupportAlgorithm::isJWSSupported($this->getAlg()))
        {
            return JoseMethod::JWS;
        }
        else
        {
            throw new UnSupportedJoseAlgorithmException($this->getAlg().' is not supported.');
        }
    }
}

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

/**
 * 지원하는 JOSE enc 알고리즘 여부를 판단하는 class
 *
 * @package com\skplanet\jose
 */
class JoseSupportEncryption
{
    /**
     * @var array JWE: A128CBC-HS256
     */
    private static $jweSupportEnc = array(
        Jwa::A128CBC_HS256
    );

    /**
     * 입력한 enc가 JWE 지원하는 알고리즘인지 확인을 한다.
     *
     * @param $enc string
     * @return bool
     */
    public static function isSupported($enc)
    {
        return in_array($enc, self::$jweSupportEnc);
    }
}

