/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.security.SecureRandom;

/**
 * 대칭 암호화 키 생성기의 기본 클래스
 */
public class CipherKeyGenerator {

	protected SecureRandom random;
	protected int strength;

	/**
	 * 생성할 키에 대한 매개변수를 설정한다. 
	 * 
	 * @param param 생성할 키에 대한 매개변수
	 */
	public void init(KeyGenerationParameters param) {
		this.random = param.getRandom();
		this.strength = (param.getStrength() + 7) / 8;
	}

	/**
	 * 키를 생성해 반환한다.
	 * 
	 * @return 생성한 키
	 */
	public byte[] generateKey() {
		byte[] key = new byte[strength];

		random.nextBytes(key);

		return key;
	}

}
