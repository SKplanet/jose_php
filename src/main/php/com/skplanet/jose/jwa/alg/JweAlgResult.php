<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-31
 * Time: 오후 12:24
 */

namespace com\skplanet\jose\jwa\alg;


class JweAlgResult
{
    private $cek;
    private $encryptedCek;

    public function __construct($cek, $encryptedCek)
    {
        $this->cek = $cek;
        $this->encryptedCek = $encryptedCek;
    }

    public function getEncryptedCek()
    {
        return $this->encryptedCek;
    }

    public function getCek()
    {
        return $this->cek;
    }
}
