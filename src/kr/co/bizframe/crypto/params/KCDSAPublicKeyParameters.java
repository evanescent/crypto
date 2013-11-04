/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

/**
 * KCDSA 공개키 매개변수
 */
public class KCDSAPublicKeyParameters 
	extends KCDSAKeyParameters {
	private BigInteger      y;

	/**
	 * 매개변수 Y와 공통 매개변수를 포함하는 생성자.
	 * 
	 * @param y 매개변수 Y
	 * @param params 공통 매개변수
	 */
    public KCDSAPublicKeyParameters(
        BigInteger      y,
        KCDSAParameters   params)
    {
        super(false, params);

        this.y = y;
    }   

    /**
     * 매개변수 Y를 반환한다.
     * 
     * @return 매개변수 Y
     */
    public BigInteger getY()
    {
        return y;
    }
}
