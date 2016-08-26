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

namespace com\skplanet\jose\jwe;

use com\skplanet\jose\JoseActionType;
use com\skplanet\jose\JoseHeader;
use com\skplanet\jose\jwa\JwaFactory;
use com\skplanet\jose\util\Base64UrlSafeEncoder;

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
        if ($args[0] == JoseActionType::SERIALIZE)
        {
            $this->joseHeader = $args[1];
            $this->payload = $args[2];
            $this->key = $args[3];
        }
        else if ($args[0] == JoseActionType::DESERIALIZE)
        {
            $this->paylod = $args[1];
            $this->key = $args[2];

            list($this->b64header, $this->b64Cek, $this->b64Iv, $this->b64CipherText, $this->b64At) =
                explode('.', $this->paylod);

            $this->joseHeader = new JoseHeader();
            $this->joseHeader->deserialize($this->b64header);

            $this->cek = Base64UrlSafeEncoder::decode($this->b64Cek);
            $this->iv = Base64UrlSafeEncoder::decode($this->b64Iv);
        }
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

    public function compactSeriaization()
    {
        if ($this->actionType == JoseActionType::SERIALIZE)
        {
            $this->serialize();
            return $this->target;
        }
        else if ($this->actionType == JoseActionType::DESERIALIZE)
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
        $jweAlg = JwaFactory::getJweAlgorithm($this->joseHeader->getAlg());
        $jweEnc = JwaFactory::getJweEncryptionAlgorithm($this->joseHeader->getEnc());

        $cekGenerator = $jweEnc->getContentEncryptionKeyGenerator();
        $cekGenerator->setUserEncryptionKey($this->cek);

        $jweAlgResult = $jweAlg->encryption($this->key, $cekGenerator);
        $cek = $jweAlgResult->getCek();

        $jweEncResult = $jweEnc->encryptAndSign($cek, $this->iv, $this->payload, $this->getAad());

        $cipherText = $jweEncResult->getCipherText();
        $at = $jweEncResult->getAt();
        $iv = $jweEncResult->getIv();

        $this->target = sprintf("%s.%s.%s.%s.%s",
            $this->joseHeader->serialize(),
            Base64UrlSafeEncoder::encode($jweAlgResult->getEncryptedCek()),
            Base64UrlSafeEncoder::encode($iv),
            Base64UrlSafeEncoder::encode($cipherText),
            Base64UrlSafeEncoder::encode($at)
        );
    }

    private function deserialize()
    {
        $jweAlg = JwaFactory::getJweAlgorithm($this->joseHeader->getAlg());
        $jweEnc = JwaFactory::getJweEncryptionAlgorithm($this->joseHeader->getEnc());

        $cek = $jweAlg->decryption($this->key, $this->cek);
        $cipherText = Base64UrlSafeEncoder::decode($this->b64CipherText);

        $this->target = $jweEnc->verifyAndDecrypt($cek, $this->iv, $cipherText, $this->b64header, $this->b64At);
    }

    public function getJoseHeader()
    {
        return $this->joseHeader;
    }
}
