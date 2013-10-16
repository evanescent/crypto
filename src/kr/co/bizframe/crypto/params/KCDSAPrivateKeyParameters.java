package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

public class KCDSAPrivateKeyParameters 
	extends KCDSAKeyParameters {
	private BigInteger      x;

    public KCDSAPrivateKeyParameters(
        BigInteger      x,
        KCDSAParameters   params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }
}
