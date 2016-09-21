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

/**
 * JOSE build configuration 처리 기능 class
 *
 * @package syruppay\jose
 */
abstract class JoseCompactBuilder
{
    /**
     * @var JoseMethod
     */
    protected $joseMethod;

    /**
     * @var JoseSerializeType
     */
    protected $joseSerializeType;

    /**
     * @var JoseActionType
     */
    protected $joseActionType;

    /**
     * @var string JOSE encryption or sign key
     */
    protected $key;

    /**
     * JOSE compact serialize 처리 serialization 설정 값 셋팅한다.
     *
     * @param $joseMethod JoseMethod
     * @param $joseActionType JoseActionType
     */
    protected function setSerializeCompactBuildConfig($joseMethod, $joseActionType)
    {
        $this->joseSerializeType = JoseSerializeType::COMPACT_SERIALIZATION;
        $this->joseMethod = $joseMethod;
        $this->joseActionType = $joseActionType;
    }

    /**
     * JOSE compact serialize 처리 deserialization 설정 값 셋팅한다.
     *
     * @param $joseActionType JoseActionType
     */
    protected function setDeserializeCompactBuildConfig($joseActionType)
    {
        $this->joseSerializeType = JoseSerializeType::COMPACT_SERIALIZATION;
        $this->joseMethod = null;
        $this->joseActionType = $joseActionType;
    }

    /**
     * 설정된 JoseActionType 반환한다.
     *
     * @return JoseActionType
     */
    public function getJoseActionType()
    {
        return $this->joseActionType;
    }

    /**
     * JOSE encryption or sign key 설정
     *
     * @param $key string
     * @return $this
     */
    public function key($key)
    {
        $this->key = $key;
        return $this;
    }

    /**
     * 설정된 config에 따른 JOSE 처리 class를 생성하여 반환한다.
     *
     * @return JoseAction
     */
    abstract public function create();
}
