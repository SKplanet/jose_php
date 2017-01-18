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

/**
 * 설정 class를 반환하는 factory class
 *
 * @package syruppay\jose
 */
class syruppay_jose_JoseBuilders
{
    /**
     * JWS compact serialize를 처리하기 위한 builder 클래스 factory method
     *
     * @return SerializationBuilder
     */
    public static function JsonSignatureCompactSerializationBuilder()
    {
        return new syruppay_jose_SerializationBuilder(JOSE_JWS, JOSE_ACTION_SERIALIZE);
    }

    /**
     * JWE compact serialize를 처리하기 위한 builder 클래스 factory method
     *
     * @return SerializationBuilder
     */
    public static function JsonEncryptionCompactSerializationBuilder()
    {
        return new syruppay_jose_SerializationBuilder(JOSE_JWE, JOSE_ACTION_SERIALIZE);
    }

    /**
     * JOSE deserialize를 처리하기 위한 builder 클래스 factory method
     *
     * @return DeserializationBuilder
     */
    public static function compactDeserializationBuilder()
    {
        return new syruppay_jose_DeserializationBuilder(JOSE_ACTION_DESERIALIZE);
    }
}
