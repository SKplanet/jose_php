<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오전 10:37
 */

namespace com\skplanet\jose;

interface JoseAction
{
    function compactSerialization();
    function compactDeserialization();
    function getJoseHeader();
}
