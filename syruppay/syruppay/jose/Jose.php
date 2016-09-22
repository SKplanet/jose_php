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

namespace syruppay\jose;

use syruppay\jose\exception\UnsupportedOperationException;

/**
 * 입력받은 configuration에 따라 JWS, JWE serialize, deserialize를 호출한다.
 *
 * @package syruppay\jose
 */
class Jose implements SerializeAction
{
    /**
     *
     * @var JoseActionType JOSE serialize, deserialize에 대한 구분 상수
     */
    private $joseActionType;

    /**
     *
     * @var JoseAction JWE 또는 JWS 처리 class
     */
    private $joseAction;

    /**
     * JOSE Action에 대한 configuration을 설정한다.
     * JoseBuilder 결과를 입력받아 {@see $joseActionType}, {@see $joseAction}을 설정한다.
     *
     * @param $joseCompactBuilder JoseCompactBuilder
     * @return $this
     */
    public function configuration($joseCompactBuilder)
    {
        $this->joseActionType = $joseCompactBuilder->getJoseActionType();
        $this->joseAction = $joseCompactBuilder->create();

        return $this;
    }

    function serialization()
    {
        if ($this->joseActionType == JoseActionType::DESERIALIZE)
            throw new UnsupportedOperationException("configuration type is deserialize");
        return $this->joseAction->compactSerialization();
    }

    function deserialization()
    {
        if ($this->joseActionType == JoseActionType::SERIALIZE)
            throw new UnsupportedOperationException("configuration type is serialize");
        return $this->joseAction->compactDeserialization();
    }

    function getJoseHeader()
    {
        return $this->joseAction->getJoseHeader();
    }
}
