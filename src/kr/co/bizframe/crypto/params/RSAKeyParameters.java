/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

/**
 * RSA 키 매개변수
 */
public class RSAKeyParameters extends AsymmetricKeyParameter {

	private BigInteger modulus;
	private BigInteger exponent;

	/**
	 * 비공개키 여부, Modulus, Exponent를 포함하는 생성자
	 * 
	 * @param isPrivate 비공개키 여부.
	 *                  <code>true</code>면 비공개키, <code>false</code>면 공개키
	 * @param modulus Modulus
	 * @param exponent Exponent
	 */
	public RSAKeyParameters(boolean isPrivate, BigInteger modulus,
			BigInteger exponent) {

		super(isPrivate);

		this.modulus = modulus;
		this.exponent = exponent;
	}

	/**
	 * Modulus를 반환한다.
	 * 
	 * @return Modulus
	 */
	public BigInteger getModulus() {
		return modulus;
	}

	/**
	 * Exponent를 반환한다.
	 * 
	 * @return Exponent
	 */
	public BigInteger getExponent() {
		return exponent;
	}
}
