<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오전 11:56
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
        parent::compactBuilder($joseMethod, $joseActionType);
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
