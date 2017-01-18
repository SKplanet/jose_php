<?php
/*
 * LICENSE : Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * JWE serialize, deserialize를 수행하는 class
 *
 * @package syruppay\jose\jwe
 */
class syruppay_jose_jwe_JweSerializer implements syruppay_jose_JoseAction
{
    /**
     * @var JoseHeader
     */
    private $joseHeader;

    /**
     * @var string JWE key encryption key
     */
    private $key;

    /**
     * @var string content encryption key
     */
    private $cek;

    /**
     * @var string content encryption iv
     */
    private $iv;

    /**
     * @var string payload
     */
    private $payload;

    /**
     * @var string base64url encoding value
     */
    private $b64header, $b64Cek, $b64Iv, $b64CipherText, $b64At;

    /**
     * JOSE header를 셋팅한다.
     *
     * @param $joseHeader JoseHeader
     */
    public function setJoseHeader($joseHeader)
    {
        $this->joseHeader = $joseHeader;
    }

    /**
     * JWE 처리할 payload를 셋팅한다.
     *
     * @param $payload string
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
    }

    /**
     * key encryption key를 셋팅한다.
     *
     * @param $key string
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * JWE value를 셋팅한다.
     * 파라미터는 JWE 규격에 유효하여야 하며 header, cek, iv, cipherText, authentication tag로 각각 파싱한다.
     *
     * @param $jweValue string
     */
    public function setParse($jweValue)
    {
        $this->payload = $jweValue;

        list($this->b64header, $this->b64Cek, $this->b64Iv, $this->b64CipherText, $this->b64At) =
            explode('.', $jweValue);

        $this->joseHeader = new syruppay_jose_JoseHeader();
        $this->joseHeader->deserialize($this->b64header);

        $this->cek = syruppay_jose_util_Base64UrlSafeEncoder::decode($this->b64Cek);
        $this->iv = syruppay_jose_util_Base64UrlSafeEncoder::decode($this->b64Iv);
    }

    /**
     * 테스트 목적으로 사용하며 contentEncryptionKey, iv를 random 생성하지 않고 입력받은 파라미터로 사용한다.
     * @param $cek
     * @param $iv
     */
    public function setUserEncryptionKey($cek, $iv)
    {
        $this->cek = $cek;
        $this->iv = $iv;
    }

    /**
     * JWE의 aad 값을 반환한다.
     *
     * @return string
     */
    private function getAad()
    {
        return $this->joseHeader->serialize();
    }

    /**
     * 입력받은 header, payload, key로 JWE를 생성하여 반환한다.
     *
     * @return string JWE
     * @throws InvalidArgumentException 규격과 다른 암호화 키 길이
     */
    public function compactSerialization()
    {
        $jweAlg = syruppay_jose_jwa_JwaFactory::getJweAlgorithm($this->joseHeader->getAlg());
        $jweEnc = syruppay_jose_jwa_JwaFactory::getJweEncryptionAlgorithm($this->joseHeader->getEnc());

        $cekGenerator = $jweEnc->getContentEncryptionKeyGenerator();
        $cekGenerator->setUserEncryptionKey($this->cek);

        $jweAlgResult = $jweAlg->encryption($this->key, $cekGenerator);
        $cek = $jweAlgResult->getCek();

        $jweEncResult = $jweEnc->encryptAndSign($cek, $this->iv, $this->payload, $this->getAad());

        $cipherText = $jweEncResult->getCipherText();
        $at = $jweEncResult->getAt();
        $iv = $jweEncResult->getIv();

        return sprintf("%s.%s.%s.%s.%s",
            $this->joseHeader->serialize(),
            syruppay_jose_util_Base64UrlSafeEncoder::encode($jweAlgResult->getEncryptedCek()),
            syruppay_jose_util_Base64UrlSafeEncoder::encode($iv),
            syruppay_jose_util_Base64UrlSafeEncoder::encode($cipherText),
            syruppay_jose_util_Base64UrlSafeEncoder::encode($at)
        );
    }

    /**
     * 입력받은 JWE, key로 payload를 추출하여 반환한다.
     *
     * @return String payload
     * @throws InvalidAuthenticationTagException JWE authentication tag verify 오류
     */
    public function compactDeserialization()
    {
        $jweAlg = syruppay_jose_jwa_JwaFactory::getJweAlgorithm($this->joseHeader->getAlg());
        $jweEnc = syruppay_jose_jwa_JwaFactory::getJweEncryptionAlgorithm($this->joseHeader->getEnc());

        $cek = $jweAlg->decryption($this->key, $this->cek);
        $cipherText = syruppay_jose_util_Base64UrlSafeEncoder::decode($this->b64CipherText);

        return $jweEnc->verifyAndDecrypt($cek, $this->iv, $cipherText, $this->b64header, $this->b64At);
    }

    /**
     * JOSE header class를 반환한다.
     *
     * @return JoseHeader
     */
    public function getJoseHeader()
    {
        return $this->joseHeader;
    }
}
