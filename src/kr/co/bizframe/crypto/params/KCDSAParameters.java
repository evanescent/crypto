package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

import kr.co.bizframe.crypto.CipherParameters;


public class KCDSAParameters
	implements CipherParameters {

	private BigInteger              g;
    private BigInteger              q;
    private BigInteger              p;
    private KCDSAValidationParameters   validation;

    public KCDSAParameters(
        BigInteger  p,
        BigInteger  q,
        BigInteger  g)
    {
        this.g = g;
        this.p = p;
        this.q = q;
    }

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

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public BigInteger getG()
    {
        return g;
    }

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

