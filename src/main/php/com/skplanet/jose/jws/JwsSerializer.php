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

namespace com\skplanet\jose\jws;

use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\JwaFactory;
use com\skplanet\jose\util\Base64UrlSafeEncoder;

class JwsSerializer
{
    private $actionType;

    private $joseHeader;
    private $payload;
    private $key;

    private $b64header;
    private $b64Payload;
    private $b64Signature;

    private $target;

    public function __construct()
    {
        $args = func_get_args();
        $this->actionType = $args[0];
        if ($args[0] == JoseActionType::SERIALIZE)
        {
            $this->joseHeader = $args[1];
            $this->payload = $args[2];
            $this->key = $args[3];
        }
        else if ($args[0] == JoseActionType::DESERIALIZE)
        {
            $this->paylod = $args[1];
            $this->key = $args[2];

            list($this->b64header, $this->b64Payload, $this->b64Signature) =
                explode('.', $this->paylod);

            $this->joseHeader = new JoseHeader();
            $this->joseHeader->deserialize($this->b64header);
        }
    }

    public function compactSeriaization()
    {
        if ($this->actionType == JoseActionType::SERIALIZE)
        {
            $this->serialize();
            return $this->target;
        }
        else if ($this->actionType == JoseActionType::DESERIALIZE)
        {
            $this->deserialize();
            return $this->target;
        }
        else
        {
            throw new \BadMethodCallException('Unknown action type');
        }
    }

    private function serialize()
    {
        $this->b64header = $this->joseHeader->serialize();
        $this->b64Payload = Base64UrlSafeEncoder::encode($this->payload);

        $jwsAlg = JwaFactory::getJwsAlgorithm($this->joseHeader->getAlg());

        $jwsAlg->sign(sprintf("%s.%s", $this->b64header, $this->b64Payload), $this->key);
        $this->b64Signature = $jwsAlg->serialize();

        $this->target = sprintf("%s.%s.%s",
            $this->b64header,
            $this->b64Payload,
            $this->b64Signature
        );
    }

    private function deserialize()
    {
        $jwsAlg = JwaFactory::getJwsAlgorithm($this->joseHeader->getAlg());
        $jwsAlg->verify(sprintf("%s.%s", $this->b64header, $this->b64Payload), $this->b64Signature, $this->key);

        $this->target = Base64UrlSafeEncoder::decode($this->b64Payload);
    }

    public function getJoseHeader()
    {
        return $this->joseHeader;
    }
}
