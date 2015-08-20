## �䱸����
PHP 5.4 �����̻� �ʿ�.
PHP 5.4, 5.6���� �׽�Ʈ �Ϸ�

## ��ġ
composer�� ����Ͽ� install�� �� �� �ֽ��ϴ�. / [packagist](https://packagist.org/packages/syruppay/jose):
```
"syruppay/jose": "v0.0.1"
```

## JWE ���� �˰���
```
alg : A128KW, A256KW
enc : A128CBC-HS256
```

## JWS ���� �˰���
```
alg : HS256
```

## �����
``` php
<?php

require_once('../../../vendor/autoload.php');

use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\Jwa;
use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\jws\JwsSerializer;
use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeaderSpec;

$src = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
$iss = 'sample';                    //SyrupPay �߱� iss
$key = '1234567890123456';          //SyrupPay �߱� �Ϻ�ȣȭ Ű

//JWE ����
//1. Jwe Header ����
$jweHeader = new JoseHeader();
$jweHeader->setAlg(Jwa::A128KW);
$jweHeader->setEnc(Jwa::A128CBC_HS256);
$jweHeader->setKid($iss);

//2. Jwe ��ȣȭ ó��
$jwe = new JweSerializer(JoseActionType::SERAILIZE, $jweHeader, $src, $key);
$enc = $jwe->compactSeriaization();

//3. SyrupPay ����

//4. ���� Jwe ������ ��ȣȭ
$jwe = new JweSerializer(JoseActionType::DESERAILIZE, $enc, $key);
$dec = $jwe->compactSeriaization();

var_dump($dec);

//JWS ����
//1. Jws Header ����
$jwsHeader = new JoseHeader();
$jwsHeader->setHeader(JoseHeaderSpec::TYP, 'JWT');
$jwsHeader->setAlg(Jwa::HS256);
$jwsHeader->setKid('sample');

//2. Jws ���� ����
$jws = new JwsSerializer(JoseActionType::SERAILIZE, $jwsHeader, $src, $key);
$enc = $jws->compactSeriaization();

//3. SyrupPay ����

//4. Jws ���� ���� �� ������ ��ȯ
$jws = new JwsSerializer(JoseActionType::DESERAILIZE, $enc, $key);
$dec = $jws->compactSeriaization();

var_dump($dec);

```
