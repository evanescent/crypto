package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

public class KCDSAPublicKeyParameters 
	extends KCDSAKeyParameters {
	private BigInteger      y;

    public KCDSAPublicKeyParameters(
        BigInteger      y,
        KCDSAParameters   params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigInteger getY()
    {
        return y;
    }
}
