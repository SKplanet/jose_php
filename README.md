# JOSE for SyrupPay

PHP로 구현한 JOSE(Javascript Object Signing and Encryption) - [RFC 7516](https://tools.ietf.org/html/rfc7516), [RFC 7515](https://tools.ietf.org/html/rfc7515) 규격입니다. 
JOSE 규격은 SyrupPay 결제 데이터 암복호화 및 AccessToken 발행 등에 사용되며 SyrupPay 서비스의 가맹점에 배포하기 위한 목적으로 라이브러리가 구현되었습니다.

## Supported PHP version
=> PHP 5.4

## Installation
### composer ([packagist](https://packagist.org/packages/syruppay/jose))
`"syruppay/jose": "v1.0.0"`

## Usage
###JWE
``` php
<?php

require_once('../../../vendor/autoload.php');

use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\Jose;
use com\skplanet\jose\JoseBuilders;
use com\skplanet\jose\JoseHeaderSpec;

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
```

###JWS
```php
<?php

require_once('../../../vendor/autoload.php');

use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\Jose;
use com\skplanet\jose\JoseBuilders;
use com\skplanet\jose\JoseHeaderSpec;

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

```

## Supported JOSE encryption algorithms

### "alg" (Algorithm) Header Parameter Values For JWE
alg Param Value|Key Management Algorithm
------|------
A128KW|AES Key Wrap with default initial value using 128 bit key
A256KW|AES Key Wrap with default initial value using 256 bit key

### "enc" (Encryption Algorithm) Header Parameter Values for JWE
enc Param Value|Content Encryption Algorithm
-------------|------
A128CBC-HS256|AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm

### "alg" (Algorithm) Header Parameter Values for JWS
alg Param Value|Digital Signature or MAC Algorithm
-----|-------
HS256|HMAC using SHA-256

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
