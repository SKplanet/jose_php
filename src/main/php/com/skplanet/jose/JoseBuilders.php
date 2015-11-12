<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오후 12:53
 */

namespace com\skplanet\jose;

class JoseBuilders
{
    public static function JsonSignatureCompactSerializationBuilder()
    {
        return new SerializationBuilder(JoseMethod::JWS, JoseActionType::SERIALIZE);
    }

    public static function JsonEncryptionCompactSerializationBuilder()
    {
        return new SerializationBuilder(JoseMethod::JWE, JoseActionType::SERIALIZE);
    }

    public static function compactDeserializationBuilder()
    {
        return new DeserializationBuilder(JoseActionType::DESERIALIZE);
    }
}
