/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * KCDSA 매개변수
 */
public class KCDSAParameters
	implements CipherParameters {

	private BigInteger              g;
    private BigInteger              q;
    private BigInteger              p;
    private KCDSAValidationParameters   validation;

    /**
     * 매개변수를 포함하는 생성자
     * 
     * @param p 매개변수 P
     * @param q 매개변수 Q
     * @param g 매개변수 G
     */
    public KCDSAParameters(
        BigInteger  p,
        BigInteger  q,
        BigInteger  g)
    {
        this.g = g;
        this.p = p;
        this.q = q;
    }

    /**
     * 매개변수와 검증 매개변수를 포함하는 생성자
     * 
     * @param p 매개변수 P
     * @param q 매개변수 Q
     * @param g 매개변수 G
     * @param params 검증 매개변수
     */
    public KCDSAParameters(
        BigInteger              p,
        BigInteger              q,
        BigInteger              g,
        KCDSAValidationParameters   params)
    {
        this.g = g;
        this.p = p;
        this.q = q;
        this.validation = params;
    }

    /**
     * 매개변수 P를 반환한다.
     * 
     * @return 매개변수 P
     */
    public BigInteger getP()
    {
        return p;
    }

    /**
     * 매개변수 Q를 반환한다.
     * 
     * @return 매개변수 Q
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * 매개변수 G를 반환한다.
     * 
     * @return 매개변수 G
     */
    public BigInteger getG()
    {
        return g;
    }

    /**
     * 검증 매개변수를 반환한다.
     * 
     * @return 검증 매개변수
     */
    public KCDSAValidationParameters getValidationParams()
    {
        return validation;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof KCDSAParameters))
        {
            return false;
        }

        KCDSAParameters    pm = (KCDSAParameters)obj;

        return (pm.getP().equals(p) && pm.getQ().equals(q) && pm.getG().equals(g));
    }

    public int hashCode()
    {
    	return getP().hashCode() ^ getQ().hashCode() ^ getG().hashCode();
    }
}

