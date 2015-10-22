# JOSE for SyrupPay

PHP로 구현한 JOSE(Javascript Object Signing and Encryption) - [RFC 7516](https://tools.ietf.org/html/rfc7516), [RFC 7515](https://tools.ietf.org/html/rfc7515) 규격입니다. 
JOSE 규격은 SyrupPay 결제 데이터 암복호화 및 AccessToken 발행 등에 사용되며 SyrupPay 서비스의 가맹점에 배포하기 위한 목적으로 라이브러리가 구현되었습니다.

## Supported PHP version
=> PHP 5.4

## Installation
### composer ([packagist](https://packagist.org/packages/syruppay/jose))
`"syruppay/jose": "v0.0.3"`

## Usage
###JWE
``` php
<?php

require_once('../../../vendor/autoload.php');

use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeaderSpec;

//암호화 할 데이터
$src = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//kid : SyrupPay가 발급하는 iss
$iss = 'sample';
//SyrupPay가 발급하는 secret
$key = '1234567890123456';

/*
 * JWE header 규격
 * alg : key wrap encryption algorithm. 아래 Supported JOSE encryption algorithms 참조
 * enc : content encryption algorithm. 아래 Supported JOSE encryption algorithms 참조
 */
$jweHeader = new JoseHeader();
$jweHeader->setAlg(Jwa::A128KW);
$jweHeader->setEnc(Jwa::A128CBC_HS256);
$jweHeader->setKid($iss);

//1. encryption
$jwe = new JweSerializer(JoseActionType::SERAILIZE, $jweHeader, $src, $key);
$enc = $jwe->compactSeriaization();

//2. verify and decryption
$jwe = new JweSerializer(JoseActionType::DESERAILIZE, $enc, $key);
$dec = $jwe->compactSeriaization();

var_dump($dec);
```

###JWS
```php
<?php

require_once('../../../vendor/autoload.php');

use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\jws\JwsSerializer;
use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeaderSpec;

//서명 할 데이터
$src = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//kid : SyrupPay가 발급하는 iss
$iss = 'sample';
//SyrupPay가 발급하는 secret
$key = '1234567890123456';

/*
 * JWS header 규격
 * alg : signature algorithm. 아래 Supported JOSE encryption algorithms 참조
 */
$jwsHeader = new JoseHeader();
$jwsHeader->setHeader(JoseHeaderSpec::TYP, 'JWT');
$jwsHeader->setAlg(Jwa::HS256);
$jwsHeader->setKid('sample');

//1. sign
$jws = new JwsSerializer(JoseActionType::SERAILIZE, $jwsHeader, $src, $key);
$enc = $jws->compactSeriaization();

//2. verify
$jws = new JwsSerializer(JoseActionType::DESERAILIZE, $enc, $key);
$dec = $jws->compactSeriaization();

var_dump($dec);

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
