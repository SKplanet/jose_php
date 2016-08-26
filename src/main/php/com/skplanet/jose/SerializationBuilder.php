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

class SerializationBuilder extends JoseCompactBuilder
{
    private $header;
    private $payload;

    public function __construct($joseMethod, $joseActionType)
    {
        parent::setSerializeCompactBuildConfig($joseMethod, $joseActionType);
        $this->header = new JoseHeader();
    }

    public function header($header)
    {
        $this->header = $header;
        return $this;
    }

    public function payload($payload)
    {
        $this->payload = $payload;
        return $this;
    }

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
                    throw new \InvalidArgumentException("unknown JoseSerializeType and JoseActionType");
                }
            case JoseSerializeType::JSON_SERIALIZATION:

            default:
                return null;
        }
    }
}
