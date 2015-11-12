<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오전 10:34
 */

namespace com\skplanet\jose;


interface SerializeAction
{
    function serialization();
    function deserialization();
    function getJoseHeader();
}
