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
use com\skplanet\jose\jwe\JweSerializer;
use com\skplanet\jose\jws\JwsSerializer;
use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeaderSpec;

$src = '{"iss":"syruppap_sample", "exp":1300819380, "isSample":true}';
$key = '1234567890123456';

#JWE Sample
$jweHeader = new JoseHeader();
$jweHeader->setAlg(Jwa::A128KW);
$jweHeader->setEnc(Jwa::A128CBC_HS256);
$jweHeader->setKid('sample');

$jwe = new JweSerializer(JoseActionType::SERAILIZE, $jweHeader, $src, $key);

//output : eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoic2FtcGxlIn0.azHNGWkwcfLGlnP_F2BX-et-E1li-DfBL3B51JzXfoPjI1fE-NpXoQ.1-lP58mjcoZaVHOov_22xg.HnEiP-KPyse6kFKaS05FuzSWiBL_20420Ngp6fpkvTRK69ggmz1xP41CmY19Q4P3M9Uu6lCfy36ZJxj_ORjGxg.w1xj1jT41AQXH72Johao8Q
$enc = $jwe->compactSeriaization();

$jwe = new JweSerializer(JoseActionType::DESERAILIZE, $enc, $key);

//output is equals $src
$dec = $jwe->compactSeriaization();

var_dump($dec);

#JWS Sample
$jwsHeader = new JoseHeader();
$jwsHeader->setHeader(JoseHeaderSpec::TYP, 'JWT');
$jwsHeader->setAlg(Jwa::HS256);
$jwsHeader->setKid('sample');

$jws = new JwsSerializer(JoseActionType::SERAILIZE, $jwsHeader, $src, $key);

//output : eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InNhbXBsZSJ9.eyJpc3MiOiJzeXJ1cHBhcF9zYW1wbGUiLCAiZXhwIjoxMzAwODE5MzgwLCAiaXNTYW1wbGUiOnRydWV9._DoT8Entk5d2cLJTp0ZJ56hI3Gd7WaL4blO2fDdAEEg
$enc = $jws->compactSeriaization();

$jws = new JwsSerializer(JoseActionType::DESERAILIZE, $enc, $key);

//output is equals $src
$dec = $jws->compactSeriaization();

var_dump($dec);





