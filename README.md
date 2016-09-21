# JOSE for SyrupPay

PHP�� ������ JOSE(Javascript Object Signing and Encryption) - [RFC 7516](https://tools.ietf.org/html/rfc7516), [RFC 7515](https://tools.ietf.org/html/rfc7515) �԰��Դϴ�. 
JOSE �԰��� SyrupPay ���� ������ �Ϻ�ȣȭ �� AccessToken ���� � ���Ǹ� SyrupPay ������ �������� �����ϱ� ���� �������� ���̺귯���� �����Ǿ����ϴ�.

## Supported PHP version
=> PHP 5.3.3

## Installation
### composer ([packagist](https://packagist.org/packages/syruppay/jose))
`"syruppay/jose": "v1.1.0"`

## Usage
###JWE
``` php
<?php

//COMPOSER�� autoload
$baseDir = "";
require_once($baseDir . '/vendor/autoload.php');

use syruppay\jose\JoseHeader;
use syruppay\jose\jwa\Jwa;
use syruppay\jose\Jose;
use syruppay\jose\JoseBuilders;
use syruppay\jose\JoseHeaderSpec;

//��ȣȭ ������
$payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//SyrupPay �߱� iss
$iss = 'sample';                                    
//SyrupPay �߱� �Ϻ�ȣȭ Ű (AES256 KeyWrap ����)
$key = '12345678901234561234567890123456';          

/*
 * JWE header �԰�
 * JoseHeaderSpec::ALG : key wrap encryption algorithm. �Ʒ� Supported JOSE encryption algorithms ����
 * JoseHeaderSpec::ENC : content encryption algorithm. �Ʒ� Supported JOSE encryption algorithms ����
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

//COMPOSER�� autoload
$baseDir = "";
require_once($baseDir . '/vendor/autoload.php');

use syruppay\jose\JoseHeader;
use syruppay\jose\jwa\Jwa;
use syruppay\jose\Jose;
use syruppay\jose\JoseBuilders;
use syruppay\jose\JoseHeaderSpec;

//Sign ������
$payload = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
//SyrupPay �߱� iss
$iss = 'sample';                                    
//SyrupPay �߱� sing Ű (HmacSha256 ����)
$key = '12345678901234561234567890123456';   

/*
 * JWS header �԰�
 * JoseHeaderSpec::ALG : signature algorithm. �Ʒ� Supported JOSE encryption algorithms ����
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
## JWE
JWE�� �Է��� payload�� �Ʒ����� �����ϴ� alg�� enc���� ����� �˰������� ��ȣȭ�մϴ�. 
Ű���� alg�� �����(�� ������) key�� �̿��Ͽ� ���������� random�ϰ� ������ CEK(content encryption key)�� ��ȣȭ�ϴ� �˰����̸�, 
Ű���� enc�� ���������� ������ CEK�� ����Ͽ� ����� ��ȣȭ �˰������� payload�� ��ȣȭ�ϸ� 
header, CEK, iv, payload�� integrity data�� �����մϴ�.

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
JWS�� Ű���� alg���� ����� �˰������� �Է��� payload�� integrity�� �����մϴ�.
alg�� �����(�� ������) key�� �̿��Ͽ� integrity data�� �����մϴ�.

### "alg" (Algorithm) Header Parameter Values for JWS
alg Param Value|Digital Signature or MAC Algorithm
-----|-------
HS256|HMAC using SHA-256

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
