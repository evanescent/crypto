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
	 * 기본 생성자
	 * 
	 * @param isPrivate 개인키 설정 여부
	 * @param modulus (n = p * q ) 공개키와 개인키에 포함되는 n 값
	 * @param exponent ( e mod phi(n) == d , d:개인키 ) 공개키에 포함되는 e 값
	 */
	public RSAKeyParameters(boolean isPrivate, BigInteger modulus,
			BigInteger exponent) {

		super(isPrivate);

		this.modulus = modulus;
		this.exponent = exponent;
	}

	/**
	 * 공개키와 개인키에 포함되는 n 값을 반환한다.
	 * @return 공개키와 개인키에 포함되는 n 값
	 */
	public BigInteger getModulus() {
		return modulus;
	}

	/**
	 * 개인키를 구하기 위한 e 값을 반환한다.
	 * @return 공개키에 포함되는 e 값
	 */
	public BigInteger getExponent() {
		return exponent;
	}
}
