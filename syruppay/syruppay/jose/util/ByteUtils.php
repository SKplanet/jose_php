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

namespace syruppay\jose\util;

class ByteUtils
{
    public static function hex2bin($src)
    {
        if (function_exists('hex2bin'))
        {
            return hex2bin($src);
        }
        return pack("H*", $src);
    }

    public static function bin2hex($src)
    {
        if (function_exists('bin2hex'))
        {
            return bin2hex($src);
        }
        return unpack("H*", $src);
    }

    public static function convertHalfWordArrayToBin(array $oct){
        $hex = '';
        foreach($oct as $b){
            $hex .= str_pad(dechex($b),2,'0',STR_PAD_LEFT);
        }
        return self::hex2bin($hex);
    }

    public static function convert2UnsignedLongBE($nbr){
        $hex = str_pad(dechex($nbr),16,'0',STR_PAD_LEFT);
        return self::hex2bin($hex);
    }
}
