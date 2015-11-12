<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-04
 * Time: 오후 1:42
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
