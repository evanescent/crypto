/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

/**
 * RSA 비공개 CRT(Chinese Remainder Theorem) 키 매개변수
 */
public class RSAPrivateCrtKeyParameters extends RSAKeyParameters {

	private BigInteger e;
	private BigInteger p;
	private BigInteger q;
	private BigInteger dP;
	private BigInteger dQ;
	private BigInteger qInv;

	/**
	 * Modulus, (공개/비공개) Exponent, P, Q, dP, dQ, qInv를 포함하는 생성자.
	 *  
	 * @param modulus Modulus
	 * @param publicExponent 공개 Exponent
	 * @param privateExponent 비공개 Exponent
	 * @param p 매개변수 P
	 * @param q 매개변수 Q
	 * @param dP 매개변수 dP
	 * @param dQ 매개변수 dQ
	 * @param qInv 매개변수 qInv
	 */
	public RSAPrivateCrtKeyParameters(BigInteger modulus,
			BigInteger publicExponent, BigInteger privateExponent,
			BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ,
			BigInteger qInv) {

		super(true, modulus, privateExponent);

		this.e = publicExponent;
		this.p = p;
		this.q = q;
		this.dP = dP;
		this.dQ = dQ;
		this.qInv = qInv;
	}

	/**
	 * 공개 Exponent를 반환한다.
	 * 
	 * @return 공개 Exponent
	 */
	public BigInteger getPublicExponent() {
		return e;
	}

	/**
	 * 매개변수 P를 반환한다.
	 * 
	 * @return 매개변수 P
	 */
	public BigInteger getP() {
		return p;
	}

	/**
	 * 매개변수 Q를 반환한다.
	 * 
	 * @return 매개변수 Q
	 */
	public BigInteger getQ() {
		return q;
	}

	/**
	 * 매개변수 dP를 반환한다.
	 * 
	 * @return 매개변수 dP
	 */
	public BigInteger getDP() {
		return dP;
	}

	/**
	 * 매개변수 dQ를 반환한다.
	 * 
	 * @return 매개변수 dQ
	 */
	public BigInteger getDQ() {
		return dQ;
	}

	/**
	 * 매개변수 qInv를 반환한다.
	 * 
	 * @return 매개변수 qInv
	 */
	public BigInteger getQInv() {
		return qInv;
	}
}
