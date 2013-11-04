/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.DerivationParameters;

/**
 * KDF(Key Derivation Function)s 매개변수
 */
public class KDFParameters
    implements DerivationParameters
{
    byte[]  iv;
    byte[]  shared;

    /**
     * 공유 비밀키와 IV를 포함하는 생성자.
     * 
     * @param shared 공유 비밀키
     * @param iv IV
     */
    public KDFParameters(
        byte[]  shared,
        byte[]  iv)
    {
        this.shared = shared;
        this.iv = iv;
    }

    /**
     * 공유 비밀키를 반환한다.
     * 
     * @return 공유 비밀키
     */
    public byte[] getSharedSecret()
    {
        return shared;
    }

    /**
     * IV를 반환한다.
     * 
     * @return IV
     */
    public byte[] getIV()
    {
        return iv;
    }
}
