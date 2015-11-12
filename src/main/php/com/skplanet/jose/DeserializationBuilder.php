<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오전 10:39
 */

namespace com\skplanet\jose;

use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\jws\JwsSerializer;

class DeserializationBuilder extends JoseCompactBuilder
{
    private $serializedSource;

    public function __construct()
    {
        $argNum = func_num_args();
        $arg = func_get_args();
        if ($argNum == 1)
        {
            parent::compactBuilder($arg[0]);
        }
        else if ($argNum == 2)
        {
            parent::compactBuilder($arg[0], $arg[1]);
        }
    }

    public function serializedSource($serializedSource)
    {
        $this->serializedSource = $serializedSource;
        return $this;
    }

    public function create()
    {
        $header = new JoseHeader();
        $header->deserialize($this->serializedSource);
        $this->joseMethod = $header->getJoseMethod();

        switch ($this->joseSerializeType)
        {
            case JoseSerializeType::COMPACT_SERIALIZATION:
                if (JoseMethod::JWE == $this->joseMethod and JoseActionType::DESERIALIZE == $this->joseActionType)
                {
                    return new JweSerializer(JoseActionType::DESERIALIZE, $this->serializedSource, $this->key);
                }
                else if (JoseMethod::JWS == $this->joseMethod and JoseActionType::DESERIALIZE == $this->joseActionType)
                {
                    return new JwsSerializer(JoseActionType::DESERIALIZE, $this->serializedSource, $this->key);
                }
                else
                {
                    throw new \InvalidArgumentException("unknown JoseSerializeType and JoseActionType");
                }
            case JoseSerializeType::JSON_SERIALIZATION:
                return null;
            default:
                return null;
        }
    }
}
