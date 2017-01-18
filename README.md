# JOSE for SyrupPay

PHP로 구현한 JOSE(Javascript Object Signing and Encryption) - RFC 7516, RFC 7515 규격입니다. JOSE 규격은 SyrupPay 결제 데이터 암복호화 및 AccessToken 발행 등에 사용되며 SyrupPay 서비스의 가맹점에 배포하기 위한 목적으로 라이브러리가 구현되었습니다.

## Supported PHP version
=> PHP 5.2.0

## Installation
### composer ([packagist](https://packagist.org/packages/syruppay/jose))
`"syruppay/jose": "v1.1.2"`

## Usage
###JWE
``` php
<?php
//COMPOSER의 autoload
$baseDir = "";
require_once($baseDir . '/vendor/autoload.php');

//암호화 데이터
$payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//SyrupPay 발급 iss
$iss = 'sample';                                    
//SyrupPay 발급 암복호화 키 (AES256 KeyWrap 기준)
$key = '12345678901234561234567890123456';          

/*
 * JWE header 규격
 * JoseHeaderSpec::ALG : key wrap encryption algorithm. 아래 Supported JOSE encryption algorithms 참조
 * JoseHeaderSpec::ENC : content encryption algorithm. 아래 Supported JOSE encryption algorithms 참조
 */
$jose = new syruppay_jose_Jose();
$jweToken = $jose->configuration(
    syruppay_jose_JoseBuilders::JsonEncryptionCompactSerializationBuilder()
        ->header(new syruppay_jose_JoseHeader(
            array(JOSE_HEADER_ALG => JWA_A256KW,
                JOSE_HEADER_ENG => JWA_A128CBC_HS256,
                JOSE_HEADER_KID => $iss)))
        ->payload($payload)
        ->key($key)
)->serialization();

var_dump($jweToken);

$jose = new syruppay_jose_Jose();
$payload = $jose->configuration(
    syruppay_jose_JoseBuilders::compactDeserializationBuilder()
        ->serializedSource($jweToken)
        ->key($key)
)->deserialization();

var_dump($payload);
```

###JWS
```php
<?php
//COMPOSER의 autoload
$baseDir = "";
require_once($baseDir . '/vendor/autoload.php');

//Sign 데이터
$payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//SyrupPay 발급 iss
$iss = 'sample';                                    
//SyrupPay 발급 sing 키 (HmacSha256 기준)
$key = '12345678901234561234567890123456';    

/*
 * JWS header 규격
 * JoseHeaderSpec::ALG : signature algorithm. 아래 Supported JOSE encryption algorithms 참조
 */
$jose = new syruppay_jose_Jose();
$jwsToken = $jose->configuration(
    syruppay_jose_JoseBuilders::JsonSignatureCompactSerializationBuilder()
        ->header(new syruppay_jose_JoseHeader(
            array(JOSE_HEADER_ALG => JWA_HS256,
                JOSE_HEADER_TYP => 'JWT',
                JOSE_HEADER_KID => $iss)))
        ->payload($payload)
        ->key($key)
)->serialization();

var_dump($jwsToken);

$jose = new syruppay_jose_Jose();
$claims = $jose->configuration(
    syruppay_jose_JoseBuilders::compactDeserializationBuilder()
        ->serializedSource($jweToken)
        ->key($key)
)->deserialization();

var_dump($claims);

```

## Supported JOSE encryption algorithms
## JWE
JWE는 입력한 payload를 아래에서 지원하는 alg와 enc에서 명시한 알고리즘으로 암호화합니다. 키워드 alg는 발행된(기 공유된) key를 이용하여 내부적으로 random하게 생성된 CEK(content encryption key)를 암호화하는 알고리즘이며, 키워드 enc는 내부적으로 생성된 CEK를 사용하여 명시한 암호화 알고리즘으로 payload를 암호화하며 header, CEK, iv, payload의 integrity data를 생성합니다.

### "alg" (Algorithm) Header Parameter Values For JWE
alg Param Value|Key Management Algorithm
------|------
A128KW|AES Key Wrap with default initial value using 128 bit key
A256KW|AES Key Wrap with default initial value using 256 bit key

### "enc" (Encryption Algorithm) Header Parameter Values for JWE
enc Param Value|Content Encryption Algorithm
-------------|------
A128CBC-HS256|AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm

## JWS
JWS는 키워드 alg에서 명시한 알고리즘으로 입력한 payload의 integrity를 보장합니다.alg는 발행된(기 공유된) key를 이용하여 integrity data를 생성합니다.

### "alg" (Algorithm) Header Parameter Values for JWS
alg Param Value|Digital Signature or MAC Algorithm
-----|-------
HS256|HMAC using SHA-256

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
