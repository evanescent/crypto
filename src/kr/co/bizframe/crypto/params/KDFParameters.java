/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.DerivationParameters;

/**
 * parameters for Key derivation functions for IEEE P1363a
 */
public class KDFParameters
    implements DerivationParameters
{
    byte[]  iv;
    byte[]  shared;

    public KDFParameters(
        byte[]  shared,
        byte[]  iv)
    {
        this.shared = shared;
        this.iv = iv;
    }

    public byte[] getSharedSecret()
    {
        return shared;
    }

    public byte[] getIV()
    {
        return iv;
    }
}
