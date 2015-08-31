<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-08-31
 * Time: 오후 2:43
 */

namespace com\skplanet\jose\jwa\enc;


class JweEncResult
{
    private $cipherText;
    private $at;
    private $iv;

    public function __construct($cipherText, $at, $iv)
    {
        $this->cipherText = $cipherText;
        $this->at = $at;
        $this->iv = $iv;
    }

    public function getCipherText()
    {
        return $this->cipherText;
    }

    public function getAt()
    {
        return $this->at;
    }

    public function getIv()
    {
        return $this->iv;
    }
}
