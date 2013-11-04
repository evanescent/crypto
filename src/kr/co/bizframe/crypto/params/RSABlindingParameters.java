/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.math.BigInteger;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * RSA 블라인딩 매개변수
 */
public class RSABlindingParameters implements CipherParameters {
	private RSAKeyParameters publicKey;
	private BigInteger blindingFactor;

	/**
	 * RSA 공개키 매개변수와 블라인딩 인자를 포함하는 생성자.
	 * 
	 * @param publicKey RSA 공개키 매개변수
	 * @param blindingFactor 블라인딩 인자
	 */
	public RSABlindingParameters(RSAKeyParameters publicKey,
			BigInteger blindingFactor) {
		if (publicKey instanceof RSAPrivateCrtKeyParameters) {
			throw new IllegalArgumentException(
					"RSA parameters should be for a public key");
		}

		this.publicKey = publicKey;
		this.blindingFactor = blindingFactor;
	}

	/**
	 * RSA 공개키 매개변수를 반환한다.
	 * 
	 * @return RSA 공개키 매개변수
	 */
	public RSAKeyParameters getPublicKey() {
		return publicKey;
	}

	/**
	 * 블라인딩 인자를 반환한다.
	 * 
	 * @return 블라인딩 인자
	 */
	public BigInteger getBlindingFactor() {
		return blindingFactor;
	}
}
