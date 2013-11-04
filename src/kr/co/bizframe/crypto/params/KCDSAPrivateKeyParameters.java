/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

/**
 * KCDSA 비밀키 매개변수
 */
public class KCDSAPrivateKeyParameters 
	extends KCDSAKeyParameters {
	private BigInteger      x;

	/**
	 * 매개변수 X와 공통 매개변수를 포함하는 생성자.
	 * 
	 * @param x 매개변수 X
	 * @param params 공통 매개변수
	 */
    public KCDSAPrivateKeyParameters(
        BigInteger      x,
        KCDSAParameters   params)
    {
        super(true, params);

        this.x = x;
    }   

    /**
     * 매개변수 X를 반환한다.
     * 
     * @return 매개변수 X
     */
    public BigInteger getX()
    {
        return x;
    }
}
