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
 * 
 */
public class KCDSAParameters
	implements CipherParameters {

	private BigInteger              g;
    private BigInteger              q;
    private BigInteger              p;
    private KCDSAValidationParameters   validation;

    /**
     * 
     * @param p
     * @param q
     * @param g
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
     * 
     * @param p
     * @param q
     * @param g
     * @param params
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
     * 
     * @return
     */
    public BigInteger getP()
    {
        return p;
    }

    /**
     * 
     * @return
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * 
     * @return
     */
    public BigInteger getG()
    {
        return g;
    }

    /**
     * 
     * @return
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

