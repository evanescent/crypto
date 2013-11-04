/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.prngs;

import java.math.BigInteger;
import java.util.Random;

import kr.co.bizframe.crypto.digests.HAS160Digest;

/**
 * KCDSA를 위한 난수생성기
 */
public class KCDSARandomGenerator {

	private HAS160Digest d = new HAS160Digest();
	
	private static final BigInteger TWO = BigInteger.valueOf(2);
	
	public BigInteger nextValue(Random random, int bitLength) {
		return new BigInteger(bitLength - 1, 40, random);
	}
	
	public BigInteger nextValue(byte[] seed, int bitLength) {
		int k = bitLength / 160;
		int r = bitLength % 160;
		
		BigInteger V;
		BigInteger R = BigInteger.valueOf(0); 
		byte[] hashValue = new byte[d.getDigestSize()];
		
		for(int i = 0; i <= k; i++) {
			d.update(seed, 0, seed.length);
			d.update((byte) (i & 0xff));
			d.doFinal(hashValue, 0);
			V = new BigInteger(1, hashValue);
			if(i == k) V = V.mod(TWO.pow(r));
			R = R.add(V.multiply(TWO.pow(160 * i)));
		}
		
		return R;
	}
	
}
