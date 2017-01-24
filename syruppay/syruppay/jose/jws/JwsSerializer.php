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
 * JWS serialize, deserialize를 수행하는 class
 *
 * @package syruppay\jose\jws
 */
class syruppay_jose_jws_JwsSerializer implements syruppay_jose_JoseAction
{
    /**
     * @var JoseHeader
     */
    private $joseHeader;

    /**
     * @var string payload
     */
    private $payload;

    /**
     * @var string JWS sign key
     */
    private $key;

    /**
     * @var string base64url encoding value
     */
    private $b64header, $b64Payload, $b64Signature;

    /**
     * JOSE header를 셋팅한다.
     *
     * @param $joseHeader JoseHeader
     */
    public function setJoseHeader($joseHeader)
    {
        $this->joseHeader = $joseHeader;
    }

    /**
     * JWS 처리할 payload를 셋팅한다.
     *
     * @param $payload string
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
    }

    /**
     * JWS value를 셋팅한다.
     * 파라미터는 JWS 규격에 유효하여야 하며 header, payload, signature로 각각 파싱한다.
     *
     * @param $jwsValue string
     */
    public function setParse($jwsValue)
    {
        $this->payload = $jwsValue;
        list($this->b64header, $this->b64Payload, $this->b64Signature) =
            explode('.', $jwsValue);

        $this->joseHeader = new syruppay_jose_JoseHeader();
        $this->joseHeader->deserialize($this->b64header);
    }

    /**
     * sign key를 셋팅한다.
     *
     * @param $key string
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * 입력받은 header, payload, key로 JWS를 생성하여 반환한다.
     *
     * @return string JWS
     * @throws InvalidArgumentException 규격과 다른 서명 키 길이
     */
    public function compactSerialization()
    {
        $this->b64header = $this->joseHeader->serialize();
        $this->b64Payload = syruppay_jose_util_Base64UrlSafeEncoder::encode($this->payload);

        $jwsAlg = syruppay_jose_jwa_JwaFactory::getJwsAlgorithm($this->joseHeader->getAlg());

        $jwsAlg->sign(sprintf("%s.%s", $this->b64header, $this->b64Payload), $this->key);
        $this->b64Signature = $jwsAlg->serialize();

        return sprintf("%s.%s.%s", $this->b64header, $this->b64Payload, $this->b64Signature);
    }

    /**
     * 입력받은 JWS, key로 payload를 추출하여 반환한다.
     *
     * @return String payload
     * @throws InvalidSignatureException JWS signature verify 오류
     */
    public function compactDeserialization()
    {
        $jwsAlg = syruppay_jose_jwa_JwaFactory::getJwsAlgorithm($this->joseHeader->getAlg());
        $jwsAlg->verify(sprintf("%s.%s", $this->b64header, $this->b64Payload), $this->b64Signature, $this->key);

        return syruppay_jose_util_Base64UrlSafeEncoder::decode($this->b64Payload);
    }

    /**
     * JOSE header class를 반환한다.
     *
     * @return JoseHeader
     */
    public function getJoseHeader()
    {
        return $this->joseHeader;
    }
}
