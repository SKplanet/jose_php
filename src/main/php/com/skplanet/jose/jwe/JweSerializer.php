<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-03
 * Time: 오전 11:21
 */

namespace com\skplanet\jose\jwe;


use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\enc\ContentEncryption;
use com\skplanet\jose\jwa\JwaFactory;
use com\skplanet\jose\util\Base64UrlSafeEncoder;
use com\skplanet\jose\util\ByteUtils;

/**
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
 *
 * Class JweSerializer
 * @package com\skplanet\jose\jwe
 */
class JweSerializer
{
    private $actionType;

    private $joseHeader;
    private $key;

    private $cek;
    private $iv;

    private $target;
    private $payload;

    private $b64header, $b64Cek, $b64Iv, $b64CipherText, $b64At;

    public function __construct()
    {
        $args = func_get_args();
        $this->actionType = $args[0];
        if ($args[0] == JoseActionType::SERAILIZE)
        {
            $this->joseHeader = $args[1];
            $this->payload = $args[2];
            $this->key = $args[3];
        }
        else if ($args[0] == JoseActionType::DESERAILIZE)
        {
            $this->paylod = $args[1];
            $this->key = $args[2];

            list($this->b64header, $this->b64Cek, $this->b64Iv, $this->b64CipherText, $this->b64At) =
                explode('.', $this->paylod);

            $this->joseHeader = new JoseHeader();
            $this->joseHeader->deserialize($this->b64header);
        }
    }

    public function getIv(ContentEncryption $jweEnc)
    {
        if (is_null($this->iv))
        {
            return $this->iv = $jweEnc->generateRandomKey($jweEnc->getIvLength());
        }

        return $this->iv;
    }

    public function setUserEncryptionKey($cek, $iv)
    {
        $this->cek = $cek;
        $this->iv = $iv;
    }

    public function getAad()
    {
        return $this->joseHeader->serialize();
    }

    public function getAl()
    {
        $aadLen = strlen($this->getAad())*8;
        return ByteUtils::convert2UnsignedLongBE($aadLen);
    }

    public function getHmac($aad, $iv, $cipherText, $al)
    {
        return implode('', array($aad, $iv, $cipherText, $al));
    }

    public function getAt($aad, $iv, $cipherText, $al)
    {
        $secret = substr($this->cek, 0, 16);
        return substr(hash_hmac('sha256', $this->getHmac($aad, $iv, $cipherText, $al), $secret, true), 0, 16); //to binary
    }

    private function verifyAt($expected, $cipherText)
    {
        $actual = Base64UrlSafeEncoder::encode(
                    $this->getAt($this->getAad(),
                        $this->iv,
                        $cipherText,
                        $this->getAl()));

        if ($actual!= $expected)
            throw new InvalidAuthenticationTagException('not match : '.$actual);
    }

    public function compactSeriaization()
    {
        if ($this->actionType == JoseActionType::SERAILIZE)
        {
            $this->serialize();
            return $this->target;
        }
        else if ($this->actionType == JoseActionType::DESERAILIZE)
        {
            $this->deserialize();
            return $this->target;
        }
        else
        {
            throw new \BadMethodCallException('Unknown action type');
        }
    }

    /**
     * @param $payload
     */
    private function serialize()
    {
        $this->b64header = $this->joseHeader->serialize();

        $jweAlg = JwaFactory::getJweAlgorithm($this->joseHeader->getAlg());
        $jweEnc = JwaFactory::getJweEncryptionAlgorithm($this->joseHeader->getEnc());

        $cekGenerator = $jweEnc->getContentEncryptionKeyGenerator();
        $cekGenerator->setUserEncryptionKey($this->cek);

        $iv = $this->getIv($jweEnc);

        $jweAlgResult = $jweAlg->encryption($this->key, $cekGenerator);
        $cek = $jweAlgResult->getCek();
        $this->b64Cek = Base64UrlSafeEncoder::encode($jweAlgResult->getEncryptedCek());
        $this->b64Iv = Base64UrlSafeEncoder::encode($iv);

        $jweEnc->encryption($this->payload, $cek, $iv);
        $cipherText = $jweEnc->getRaw();
        $this->b64CipherText = $jweEnc->serialize();

        $aad = $this->getAad();
        $al = $this->getAl();

        $this->b64At = Base64UrlSafeEncoder::encode($this->getAt($aad, $iv, $cipherText, $al));

        $this->target = sprintf("%s.%s.%s.%s.%s",
            $this->b64header,
            $this->b64Cek,
            $this->b64Iv,
            $this->b64CipherText,
            $this->b64At
        );
    }

    private function deserialize()
    {
        $jweAlg = JwaFactory::getJweAlgorithm($this->joseHeader->getAlg());
        $jweEnc = JwaFactory::getJweEncryptionAlgorithm($this->joseHeader->getEnc());

        $jweAlg->decryption($this->key, $jweAlg->deserialize($this->b64Cek));
        $this->cek = $jweAlg->getRaw();
        $this->iv = Base64UrlSafeEncoder::decode($this->b64Iv);

        $cipherText = Base64UrlSafeEncoder::decode($this->b64CipherText);
        $this->verifyAt($this->b64At, $cipherText);

        $jweEnc->decryption($cipherText, $this->cek, $this->iv);
        $this->target = $jweEnc->getRaw();
    }

    public function getJoseHeader()
    {
        return $this->joseHeader;
    }
}
