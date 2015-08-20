## 요구사항
PHP 5.4 버전이상 필요.
PHP 5.4, 5.6에서 테스트 완료

## 설치
composer를 사용하여 install을 할 수 있습니다. / [packagist](https://packagist.org/packages/syruppay/jose):
```
"syruppay/jose": "v0.0.1"
```

## JWE 지원 알고리즘
```
alg : A128KW, A256KW
enc : A128CBC-HS256
```

## JWS 지원 알고리즘
```
alg : HS256
```

## 사용방법
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
$iss = 'sample';                    //SyrupPay 발급 iss
$key = '1234567890123456';          //SyrupPay 발급 암복호화 키

//JWE 예제
//1. Jwe Header 설정
$jweHeader = new JoseHeader();
$jweHeader->setAlg(Jwa::A128KW);
$jweHeader->setEnc(Jwa::A128CBC_HS256);
$jweHeader->setKid($iss);

//2. Jwe 암호화 처리
$jwe = new JweSerializer(JoseActionType::SERAILIZE, $jweHeader, $src, $key);
$enc = $jwe->compactSeriaization();

//3. SyrupPay 연동

//4. 수신 Jwe 데이터 복호화
$jwe = new JweSerializer(JoseActionType::DESERAILIZE, $enc, $key);
$dec = $jwe->compactSeriaization();

var_dump($dec);

//JWS 예제
//1. Jws Header 설정
$jwsHeader = new JoseHeader();
$jwsHeader->setHeader(JoseHeaderSpec::TYP, 'JWT');
$jwsHeader->setAlg(Jwa::HS256);
$jwsHeader->setKid('sample');

//2. Jws 서명 생성
$jws = new JwsSerializer(JoseActionType::SERAILIZE, $jwsHeader, $src, $key);
$enc = $jws->compactSeriaization();

//3. SyrupPay 연동

//4. Jws 서명 검증 및 데이터 반환
$jws = new JwsSerializer(JoseActionType::DESERAILIZE, $enc, $key);
$dec = $jws->compactSeriaization();

var_dump($dec);

```
