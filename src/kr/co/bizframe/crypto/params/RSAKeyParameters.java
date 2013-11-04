/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

/**
 * 
 */
public class RSAKeyParameters extends AsymmetricKeyParameter {

	private BigInteger modulus;
	private BigInteger exponent;

	/**
	 * 
	 * @param isPrivate
	 * @param modulus
	 * @param exponent
	 */
	public RSAKeyParameters(boolean isPrivate, BigInteger modulus,
			BigInteger exponent) {

		super(isPrivate);

		this.modulus = modulus;
		this.exponent = exponent;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getModulus() {
		return modulus;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getExponent() {
		return exponent;
	}
}
