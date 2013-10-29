/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.KeyGenerationParameters;

/**
 * 
 */
public class RSAKeyGenerationParameters extends KeyGenerationParameters {

	private BigInteger publicExponent;
	private int certainty;

	/**
	 * 
	 * @param publicExponent
	 * @param random
	 * @param strength
	 * @param certainty
	 */
	public RSAKeyGenerationParameters(BigInteger publicExponent,
			SecureRandom random, int strength, int certainty) {
		super(random, strength);

		if (strength < 12) {
			throw new IllegalArgumentException("key strength too small");
		}

		//
		// public exponent cannot be even
		//
		if (!publicExponent.testBit(0)) {
			throw new IllegalArgumentException("public exponent cannot be even");
		}

		this.publicExponent = publicExponent;
		this.certainty = certainty;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getPublicExponent() {
		return publicExponent;
	}

	/**
	 * 
	 * @return
	 */
	public int getCertainty() {
		return certainty;
	}
}
