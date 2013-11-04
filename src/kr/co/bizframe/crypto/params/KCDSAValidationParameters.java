/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

import kr.co.bizframe.crypto.util.Arrays;

/**
 * KCDSA 검증 매개변수
 */
public class KCDSAValidationParameters {

	private BigInteger          j;
    private byte[]              seed;
    private int                 counter;

    /**
     * 매개변수를 포함하는 생성자
     * 
     * @param j 매개변수 J
     * @param seed 시드
     * @param counter 카운터
     */
    public KCDSAValidationParameters(
    	BigInteger  j,
        byte[]      seed,
        int         counter)
    {
    	this.j = j;
        this.seed = seed;
        this.counter = counter;
    }

    /**
     * 매개변수 J를 반환한다.
     * 
     * @return 매개변수 J
     */
    public BigInteger getJ() {
    	return j;
    }

    /**
     * 시드를 반환한다.
     * 
     * @return 시드
     */
    public byte[] getSeed()
    {
        return seed;
    }

    /**
     * 카운터를 반환한다.
     * 
     * @return 카운터
     */
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

