<?php
use syruppay\jose\Jose;
use syruppay\jose\JoseBuilders;
use syruppay\jose\JoseHeader;
use syruppay\jose\JoseHeaderSpec;
use syruppay\jose\jwa\Jwa;

require_once  "d:\\intellij_workspace\\php_jose\\vendor\\autoload.php";

$payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
$iss = 'sample';                                    //SyrupPay 발급 iss
$key = '12345678901234561234567890123456';          //SyrupPay 발급 암복호화 키

function with($object){ return $object; }

$jose = new Jose();
$jweToken = $jose->configuration(
    JoseBuilders::JsonEncryptionCompactSerializationBuilder()
        ->header(new JoseHeader(
            array(JoseHeaderSpec::ALG => Jwa::A256KW,
                JoseHeaderSpec::ENC => Jwa::A128CBC_HS256,
                JoseHeaderSpec::KID => $iss)))
        ->payload($payload)
        ->key($key)
)->serialization();

var_dump($jweToken);

$jose = new Jose();
$payload = $jose->configuration(
    JoseBuilders::compactDeserializationBuilder()
        ->serializedSource($jweToken)
        ->key($key)
)->deserialization();

var_dump($payload);

$jose = new Jose();
$jwsToken = $jose->configuration(
    JoseBuilders::JsonSignatureCompactSerializationBuilder()
        ->header(new JoseHeader(
            array(JoseHeaderSpec::ALG => Jwa::HS256,
                JoseHeaderSpec::TYP => 'JWT',
                JoseHeaderSpec::KID => $iss)))
        ->payload($payload)
        ->key($key)
)->serialization();

var_dump($jwsToken);

$jose = new Jose();
$claims = $jose->configuration(
    JoseBuilders::compactDeserializationBuilder()
    ->serializedSource($jweToken)
    ->key($key)
)->deserialization();

var_dump($claims);





