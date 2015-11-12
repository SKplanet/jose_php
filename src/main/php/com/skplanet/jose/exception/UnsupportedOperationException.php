<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오후 1:01
 */

namespace com\skplanet\jose\exception;


class UnsupportedOperationException extends \Exception
{
    public function __construct($message, $code=0)
    {
        parent::__construct($message, $code);
    }
}
