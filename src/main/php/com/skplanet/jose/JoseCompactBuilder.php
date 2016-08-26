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

abstract class JoseCompactBuilder
{
    protected $joseMethod;
    protected $joseSerializeType;
    protected $joseActionType;

    protected $key;

    protected function setSerializeCompactBuildConfig($joseMethod, $joseActionType)
    {
        $this->joseSerializeType = JoseSerializeType::COMPACT_SERIALIZATION;
        $this->joseMethod = $joseMethod;
        $this->joseActionType = $joseActionType;
    }

    protected function setDeserializeCompactBuildConfig($joseActionType)
    {
        $this->joseSerializeType = JoseSerializeType::COMPACT_SERIALIZATION;
        $this->joseMethod = null;
        $this->joseActionType = $joseActionType;
    }

    public function getJoseActionType()
    {
        return $this->joseActionType;
    }

    public function key($key)
    {
        $this->key = $key;
        return $this;
    }

    abstract public function create();
}
