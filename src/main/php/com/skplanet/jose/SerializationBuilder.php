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

use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\jws\JwsSerializer;

/**
 * JOSE serialize configuration 처리 기능 class
 *
 * @package com\skplanet\jose
 */
class SerializationBuilder extends JoseCompactBuilder
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
        $this->header = new JoseHeader();
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
            case JoseSerializeType::COMPACT_SERIALIZATION:
                if (JoseMethod::JWE == $this->joseMethod and JoseActionType::SERIALIZE == $this->joseActionType)
                {
                    return new JweSerializer(JoseActionType::SERIALIZE, $this->header, $this->payload, $this->key);
                }
                else if (JoseMethod::JWS == $this->joseMethod and JoseActionType::SERIALIZE == $this->joseActionType)
                {
                    return new JwsSerializer(JoseActionType::SERIALIZE, $this->header, $this->payload, $this->key);
                }
                else
                {
                    throw new \InvalidArgumentException("Unknown JoseSerializeType and JoseActionType");
                }
            case JoseSerializeType::JSON_SERIALIZATION:

            default:
                return null;
        }
    }
}
