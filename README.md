# JOSE for SyrupPay

PHP�� ������ JOSE(Javascript Object Signing and Encryption) - [RFC 7516](https://tools.ietf.org/html/rfc7516), [RFC 7515](https://tools.ietf.org/html/rfc7515) �԰��Դϴ�. 
JOSE �԰��� SyrupPay ���� ������ �Ϻ�ȣȭ �� AccessToken ���� � ���Ǹ� SyrupPay ������ �������� �����ϱ� ���� �������� ���̺귯���� �����Ǿ����ϴ�.

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

//��ȣȭ �� ������
$src = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//kid : SyrupPay�� �߱��ϴ� iss
$iss = 'sample';
//SyrupPay�� �߱��ϴ� secret
$key = '1234567890123456';

/*
 * JWE header �԰�
 * alg : key wrap encryption algorithm. �Ʒ� Supported JOSE encryption algorithms ����
 * enc : content encryption algorithm. �Ʒ� Supported JOSE encryption algorithms ����
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

//���� �� ������
$src = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//kid : SyrupPay�� �߱��ϴ� iss
$iss = 'sample';
//SyrupPay�� �߱��ϴ� secret
$key = '1234567890123456';

/*
 * JWS header �԰�
 * alg : signature algorithm. �Ʒ� Supported JOSE encryption algorithms ����
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
