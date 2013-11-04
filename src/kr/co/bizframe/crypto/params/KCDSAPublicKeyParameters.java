/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

/**
 * 
 */
public class KCDSAPublicKeyParameters 
	extends KCDSAKeyParameters {
	private BigInteger      y;

	/**
	 * 
	 * @param y
	 * @param params
	 */
    public KCDSAPublicKeyParameters(
        BigInteger      y,
        KCDSAParameters   params)
    {
        super(false, params);

        this.y = y;
    }   

    /**
     * 
     * @return
     */
    public BigInteger getY()
    {
        return y;
    }
}
