<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-31
 * Time: 오후 12:04
 */

namespace com\skplanet\jose\jwa\enc;


class ContentEncryptKeyGenerator
{
    private $keyLength;
    private $cek;

    public function __construct($keyLength)
    {
        $this->keyLength = $keyLength;
    }

    public function setUserEncryptionKey($cek)
    {
        $this->cek = $cek;
    }

    public function generateRandomKey()
    {
        if (is_null($this->cek))
        {
            $this->cek = crypt_random_string($this->keyLength);
        }

        return $this->cek;
    }
}
