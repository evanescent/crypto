/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import java.security.SecureRandom;

/**
 * 키 생성기에 설정할 매개변수의 기본 클래스
 */
public class KeyGenerationParameters {

	private SecureRandom random;
	private int strength;

	/**
	 * 난수생성기와 강도(비트)를 설정한다.
	 * 
	 * @param random 난수생성기
	 * @param strength 생성할 키가 가질 강도(비트)
	 */
	public KeyGenerationParameters(SecureRandom random, int strength) {
		this.random = random;
		this.strength = strength;
	}

	/**
	 * 생성기에서 사용할 난수생성기를 반환한다.
	 * 
	 * @return 생성기에서 사용할 난수생성기
	 */
	public SecureRandom getRandom() {
		return random;
	}

	/**
	 * 생성기에 의해 제작될 키의 강도(비트)를 반환한다.
	 * 
	 * @return 생성기에 의해 제작될 키의 강도(비트)
	 */
	public int getStrength() {
		return strength;
	}
}
