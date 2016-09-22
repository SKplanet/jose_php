<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-04
 * Time: 오후 2:23
 */

namespace syruppay\jose\jws;


use syruppay\jose\JoseActionType;
use syruppay\jose\JoseHeader;
use syruppay\jose\JoseHeaderSpec;
use syruppay\jose\jwa\Jwa;

class JwsSerializeTest extends \PHPUnit_Framework_TestCase
{
    public function testSerialize()
    {
        $payload = '{"iss":"joe", "exp":1300819380, "http://example.com/is_root":true}';
		$key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

		$expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCAiZXhwIjoxMzAwODE5MzgwLCAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.yyo3y75o_kyTXfccX9iYY7agjAAYLlkVpR2n15-Gz_A';

        $header = new JoseHeader();
        $header->setHeader(JoseHeaderSpec::TYP, 'JWT');
        $header->setAlg(Jwa::HS256);

        $jws = new JwsSerializer();
        $jws->setJoseHeader($header);
        $jws->setKey($key);
        $jws->setPayload($payload);
        $actual = $jws->compactSerialization();

        $this->assertEquals($expected, $actual);
    }

    public function testVerify()
    {
        $expected = '{"iss":"joe", "exp":1300819380, "http://example.com/is_root":true}';
        $src = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCAiZXhwIjoxMzAwODE5MzgwLCAiaHR0cDovL2V4YW1wbGUuY29tL2lzX3Jvb3QiOnRydWV9.yyo3y75o_kyTXfccX9iYY7agjAAYLlkVpR2n15-Gz_A';
        $key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

        $jws = new JwsSerializer();
        $jws->setKey($key);
        $jws->setParse($src);
        $actual = $jws->compactDeserialization();

        $this->assertEquals($expected, $actual);
    }
}
