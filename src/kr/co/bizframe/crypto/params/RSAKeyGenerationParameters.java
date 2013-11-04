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
 * RSA 키 생성 매개변수
 */
public class RSAKeyGenerationParameters extends KeyGenerationParameters {

	private BigInteger publicExponent;
	private int certainty;

	/**
	 * Exponent, 난수생성기, 강도 및 확실성을 포함하는 생성자
	 * 
	 * @param publicExponent Exponent
	 * @param random 난수생성기
	 * @param strength 강도
	 * @param certainty 확실성
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
	 * Exponent를 반환한다.
	 * 
	 * @return Exponent
	 */
	public BigInteger getPublicExponent() {
		return publicExponent;
	}

	/**
	 * 확실성을 반환한다.
	 * 
	 * @return 확실성
	 */
	public int getCertainty() {
		return certainty;
	}
}
