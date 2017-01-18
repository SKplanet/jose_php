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
 * JOSE header 관리 class
 *
 * @package syruppay\jose
 */
class syruppay_jose_JoseHeader
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
            throw new InvalidArgumentException('Usage : new JoseHeader(array(JoseHeaderSpec => $value)');
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
        $supported = new syruppay_jose_JoseSupportAlgorithm();
        if (!$supported->isSupported($alg))
        {
            throw new syruppay_jose_exception_UnSupportedJoseAlgorithmException("unknown header 'alg' value : ".$alg);
        }

        $this->header[JOSE_HEADER_ALG] = $alg;
        return $this;
    }

    /**
     * header에 셋팅된 alg value를 반환한다.
     *
     * @return string
     */
    public function getAlg()
    {
        return $this->header[JOSE_HEADER_ALG];
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
        $supported = new syruppay_jose_JoseSupportEncryption();
        if (!$supported->isSupported($enc))
        {
            throw new syruppay_jose_exception_UnSupportedJoseAlgorithmException("unknown header 'enc' value : ".$enc);
        }

        $this->header[JOSE_HEADER_ENG] = $enc;
        return $this;
    }

    /**
     * header에 셋팅된 enc value를 반환한다.
     *
     * @return mixed
     */
    public function getEnc()
    {
        return $this->header[JOSE_HEADER_ENG];
    }

    /**
     * JOSE 규격 kid를 세팅한다.
     *
     * @param $kid string
     * @return $this
     */
    public function setKid($kid)
    {
        $this->header[JOSE_HEADER_KID] = $kid;
        return $this;
    }

    /**
     * header에 셋팅된 kid value를 반환한다.
     *
     * @return mixed
     */
    public function getKid()
    {
        return $this->header[JOSE_HEADER_KID];
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
    public function toJson()
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
        return syruppay_jose_util_Base64UrlSafeEncoder::encode($this->toJson());
    }

    /**
     * 입력한 JWE, JWS 값 중에서 header 부분을 추출하여 header로 변환한다.
     *
     * @param $src JWE or JWS value
     */
    public function deserialize($src)
    {
        list($headerToken, $rest) = array_pad(explode(".", $src, 2), 2, null);
        $this->header = json_decode(syruppay_jose_util_Base64UrlSafeEncoder::decode($headerToken), true);
    }

    /**
     * alg에 따른 JOSE type를 반환한다.
     *
     * @return JoseMethod
     * @throws UnSupportedJoseAlgorithmException 지원하지 않는 alg면 exception 발생
     */
    public function getJoseMethod()
    {
        $supported = new syruppay_jose_JoseSupportAlgorithm();
        if ($supported->isJWESupported($this->getAlg()))
        {
            return JOSE_JWE;
        }
        else if ($supported->isJWSSupported($this->getAlg()))
        {
            return JOSE_JWS;
        }
        else
        {
            throw new syruppay_jose_exception_UnSupportedJoseAlgorithmException($this->getAlg().' is not supported.');
        }
    }
}





