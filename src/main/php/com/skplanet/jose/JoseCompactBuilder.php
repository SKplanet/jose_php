<?php
/**
 * Created by IntelliJ IDEA.
 * User: 1000808
 * Date: 2015-11-11
 * Time: 오후 6:48
 */

namespace com\skplanet\jose;

abstract class JoseCompactBuilder
{
    protected $joseMethod;
    protected $joseSerializeType;
    protected $joseActionType;

    protected $key;

    protected function compactBuilder()
    {
        $argNum = func_num_args();
        $arg = func_get_args();

        if ($argNum == 1)
        {
            $this->joseMethod = null;
            $this->joseSerializeType = JoseSerializeType::COMPACT_SERIALIZATION;
            $this->joseActionType = $arg[0];
        }
        else if ($argNum == 2)
        {
            $this->joseMethod = $arg[0];
            $this->joseSerializeType = JoseSerializeType::COMPACT_SERIALIZATION;
            $this->joseActionType = $arg[1];
        }
        else if ($argNum == 3)
        {
            $this->joseMethod = $arg[0];
            $this->joseSerializeType = $arg[1];
            $this->joseActionType = $arg[2];
        }
    }

    public function getJoseActionType()
    {
        return $this->joseActionType;
    }

    public function key($key)
    {
        $this->key = $key;
        return $this;
    }

    abstract public function create();
}
