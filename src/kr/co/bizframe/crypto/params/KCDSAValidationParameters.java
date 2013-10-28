/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

import kr.co.bizframe.crypto.util.Arrays;

public class KCDSAValidationParameters {

	private BigInteger          j;
    private byte[]              seed;
    private int                 counter;

    public KCDSAValidationParameters(
    	BigInteger  j,
        byte[]      seed,
        int         counter)
    {
    	this.j = j;
        this.seed = seed;
        this.counter = counter;
    }

    public BigInteger getJ() {
    	return j;
    }

    public byte[] getSeed()
    {
        return seed;
    }

    public int getCounter()
    {
        return counter;
    }

    public int hashCode()
    {
        return j.hashCode() ^ counter ^ Arrays.hashCode(seed);
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof KCDSAValidationParameters))
        {
            return false;
        }

        KCDSAValidationParameters  other = (KCDSAValidationParameters)o;

        if ( !j.equals(other.getJ()) )
        {
        	return false;
        }

        if (other.counter != this.counter)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }
}

