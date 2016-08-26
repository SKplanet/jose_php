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

use com\skplanet\jose\exception\UnsupportedOperationException;

class Jose implements SerializeAction
{
    private $joseActionType;
    private $joseAction;

    public function __construct()
    {
        return $this;
    }

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
        return $this->joseAction->compactSeriaization();
    }

    function deserialization()
    {
        if ($this->joseActionType == JoseActionType::SERIALIZE)
            throw new UnsupportedOperationException("configuration type is serialize");
        return $this->joseAction->compactSeriaization();
    }

    function getJoseHeader()
    {
        return $this->joseAction->getJoseHeader();
    }
}
