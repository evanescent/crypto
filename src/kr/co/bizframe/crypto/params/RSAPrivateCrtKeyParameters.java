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
public class RSAPrivateCrtKeyParameters extends RSAKeyParameters {

	private BigInteger e;
	private BigInteger p;
	private BigInteger q;
	private BigInteger dP;
	private BigInteger dQ;
	private BigInteger qInv;

	/**
	 * 
	 * @param modulus
	 * @param publicExponent
	 * @param privateExponent
	 * @param p
	 * @param q
	 * @param dP
	 * @param dQ
	 * @param qInv
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
	 * 
	 * @return
	 */
	public BigInteger getPublicExponent() {
		return e;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getP() {
		return p;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getQ() {
		return q;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getDP() {
		return dP;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getDQ() {
		return dQ;
	}

	/**
	 * 
	 * @return
	 */
	public BigInteger getQInv() {
		return qInv;
	}
}
