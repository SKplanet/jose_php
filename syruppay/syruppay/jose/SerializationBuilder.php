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
 * JOSE serialize configuration 처리 기능 class
 *
 * @package syruppay\jose
 */
class syruppay_jose_SerializationBuilder extends syruppay_jose_JoseCompactBuilder
{
    /**
     * @var JoseHeader
     */
    private $header;

    /**
     * @var string (JSON)
     */
    private $payload;

    public function __construct($joseMethod, $joseActionType)
    {
        parent::setSerializeCompactBuildConfig($joseMethod, $joseActionType);
        $this->header = new syruppay_jose_JoseHeader();
    }

    /**
     * JoseHeader를 설정한다.
     *
     * @param $header JoseHeader
     * @return $this
     */
    public function header($header)
    {
        $this->header = $header;
        return $this;
    }

    /**
     * serialize할 payload value를 설정한다.
     *
     * @param $payload string (JSON)
     * @return $this
     */
    public function payload($payload)
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * 설정된 config에 따른 JOSE 처리 class를 생성하여 반환한다.
     *
     * @return JoseAction json serialize 인 경우 null을 반환한다.
     * @throws \InvalidArgumentException 유효하지 않은 JoseMethod 또는 유효하지 않은 JoseActionType
     */
    public function create()
    {
        switch ($this->joseSerializeType)
        {
            case JOSE_COMPACT_SERIALIZATION:
                if (JOSE_JWE == $this->joseMethod and JOSE_ACTION_SERIALIZE == $this->joseActionType)
                {
                    $serializer = new syruppay_jose_jwe_JweSerializer();
                }
                else if (JOSE_JWS == $this->joseMethod and JOSE_ACTION_SERIALIZE == $this->joseActionType)
                {
                    $serializer = new syruppay_jose_jws_JwsSerializer();
                }
                else
                {
                    throw new InvalidArgumentException("Unknown JoseSerializeType and JoseActionType");
                }

                $serializer->setJoseHeader($this->header);
                $serializer->setPayload($this->payload);
                $serializer->setKey($this->key);

                return $serializer;
            case JOSE_JSON_SERIALIZATION:

            default:
                return null;
        }
    }
}
