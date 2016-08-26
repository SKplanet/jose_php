<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-04
 * Time: 오후 5:07
 */
require_once('../../../vendor/autoload.php');

use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\Jose;
use com\skplanet\jose\JoseBuilders;
use com\skplanet\jose\JoseHeaderSpec;

$payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
$iss = 'sample';                                    //SyrupPay 발급 iss
$key = '12345678901234561234567890123456';          //SyrupPay 발급 암복호화 키

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





