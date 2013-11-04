/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import java.security.SecureRandom;

import kr.co.bizframe.crypto.KeyGenerationParameters;

/**
 * KCDSA 키 생성 매개변수
 */
public class KCDSAKeyGenerationParameters
	extends KeyGenerationParameters {

	private KCDSAParameters params;

	/**
	 * 난수생성기와 KCDSA 매개변수를 설정한다.
	 * 
	 * @param random 난수생성기
	 * @param params KCDSA 매개변수
	 */
	public KCDSAKeyGenerationParameters(
			SecureRandom random,
			KCDSAParameters params) {
		super(random, params.getP().bitLength() - 1);

		this.params = params;
	}

	/**
	 * KCDSA 매개변수를 반환한다.
	 * 
	 * @return KCDSA 매개변수
	 */
	public KCDSAParameters getParameters() {
		return params;
	}
}
