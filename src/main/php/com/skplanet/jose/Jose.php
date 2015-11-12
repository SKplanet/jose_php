<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-12
 * Time: 오후 12:55
 */

namespace com\skplanet\jose;

use com\skplanet\jose\exception\UnsupportedOperationException;

class Jose implements SerializeAction
{
    private $joseActionType;
    private $joseAction;

    public function __construct()
    {
        return $this;
    }

    public function configuration($joseCompactBuilder)
    {
        $this->joseActionType = $joseCompactBuilder->getJoseActionType();
        $this->joseAction = $joseCompactBuilder->create();

        return $this;
    }

    function serialization()
    {
        if ($this->joseActionType == JoseActionType::DESERIALIZE)
            throw new UnsupportedOperationException("configuration type is deserialize");
        return $this->joseAction->compactSeriaization();
    }

    function deserialization()
    {
        if ($this->joseActionType == JoseActionType::SERIALIZE)
            throw new UnsupportedOperationException("configuration type is serialize");
        return $this->joseAction->compactSeriaization();
    }

    function getJoseHeader()
    {
        return $this->joseAction->getJoseHeader();
    }
}
